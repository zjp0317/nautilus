/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Thread management for memcached.
 */
#ifdef __Nautilus__
#include "memcached.h"
#else
#include "memcached.h"
#include <pthread.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#endif

#define ITEMS_PER_ALLOC 64

/* An item in the connection queue. */
enum conn_queue_item_modes {
    queue_new_conn,   /* brand new connection. */
    queue_redispatch, /* redispatching from side thread */
};
typedef struct conn_queue_item CQ_ITEM;
struct conn_queue_item {
    int               sfd;
    int               read_buffer_size;
    conn *c;
    CQ_ITEM          *next;
};

/* A connection queue. */
typedef struct conn_queue CQ;
struct conn_queue {
    CQ_ITEM *head;
    CQ_ITEM *tail;
    pthread_mutex_t lock;
};

/* Locks for cache LRU operations */
pthread_mutex_t lru_locks[POWER_LARGEST];

/* Connection lock around accepting new connections */
pthread_mutex_t conn_lock = PTHREAD_MUTEX_INITIALIZER;

#if !defined(HAVE_GCC_ATOMICS) && !defined(__sun)
pthread_mutex_t atomics_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* Lock to cause worker threads to hang up after being woken */
static pthread_mutex_t worker_hang_lock;

/* Free list of CQ_ITEM structs */
static CQ_ITEM *cqi_freelist;
static pthread_mutex_t cqi_freelist_lock;

static pthread_mutex_t *item_locks;
/* size of the item lock hash table */
static uint32_t item_lock_count;
unsigned int item_lock_hashpower;
#define hashsize(n) ((unsigned long int)1<<(n))
#define hashmask(n) (hashsize(n)-1)

static NK_MEMCACHED_THREAD *threads;

/* item_lock() must be held for an item before any modifications to either its
 * associated hash bucket, or the structure itself.
 * LRU modifications must hold the item lock, and the LRU lock.
 * LRU's accessing items must item_trylock() before modifying an item.
 * Items accessible from an LRU must not be freed or modified
 * without first locking and removing from the LRU.
 */

void item_lock(uint32_t hv) {
    mutex_lock(&item_locks[hv & hashmask(item_lock_hashpower)]);
}

void *item_trylock(uint32_t hv) {
    pthread_mutex_t *lock = &item_locks[hv & hashmask(item_lock_hashpower)];
    if (pthread_mutex_trylock(lock) == 0) {
        return lock;
    }
    return NULL;
}

void item_trylock_unlock(void *lock) {
    mutex_unlock((pthread_mutex_t *) lock);
}

void item_unlock(uint32_t hv) {
    mutex_unlock(&item_locks[hv & hashmask(item_lock_hashpower)]);
}

/*
 * Initializes a connection queue.
 */
static void cq_init(CQ *cq) {
    pthread_mutex_init(&cq->lock, NULL);
    cq->head = NULL;
    cq->tail = NULL;
}

/*
 * Looks for an item on a connection queue, but doesn't block if there isn't
 * one.
 * Returns the item, or NULL if no item is available
 */
static CQ_ITEM *cq_pop(CQ *cq) {
    CQ_ITEM *item;

    pthread_mutex_lock(&cq->lock);
    item = cq->head;
    if (NULL != item) {
        cq->head = item->next;
        if (NULL == cq->head)
            cq->tail = NULL;
    }
    pthread_mutex_unlock(&cq->lock);

    return item;
}

/*
 * Adds an item to a connection queue.
 */
static void cq_push(CQ *cq, CQ_ITEM *item) {
    item->next = NULL;

    pthread_mutex_lock(&cq->lock);
    if (NULL == cq->tail)
        cq->head = item;
    else
        cq->tail->next = item;
    cq->tail = item;
    pthread_mutex_unlock(&cq->lock);
}

/*
 * Returns a fresh connection queue item.
 */
static CQ_ITEM *cqi_new(void) {
    CQ_ITEM *item = NULL;
    pthread_mutex_lock(&cqi_freelist_lock);
    if (cqi_freelist) {
        item = cqi_freelist;
        cqi_freelist = item->next;
    }
    pthread_mutex_unlock(&cqi_freelist_lock);

    if (NULL == item) {
        int i;
        item = malloc(sizeof(CQ_ITEM) * ITEMS_PER_ALLOC);
        if(NULL == item)
            return NULL;

        for (i = 2; i < ITEMS_PER_ALLOC; i++)
            item[i - 1].next = &item[i];

        pthread_mutex_lock(&cqi_freelist_lock);
        item[ITEMS_PER_ALLOC - 1].next = cqi_freelist;
        cqi_freelist = &item[1];
        pthread_mutex_unlock(&cqi_freelist_lock);
    }

    return item;
}

/*
 * Frees a connection queue item (adds it to the freelist.)
 */
static void cqi_free(CQ_ITEM *item) {
    pthread_mutex_lock(&cqi_freelist_lock);
    item->next = cqi_freelist;
    cqi_freelist = item;
    pthread_mutex_unlock(&cqi_freelist_lock);
}

/*
 * Creates a worker thread.
 */
static int create_worker(void *(*func)(void *), void *arg) {
    pthread_attr_t  attr;
    int             ret;

    pthread_attr_init(&attr);

    if ((ret = pthread_create(&((NK_MEMCACHED_THREAD*)arg)->thread_id, &attr, func, arg)) != 0) {
        fprintf(stderr, "Can't create thread: %s\n",
                strerror(ret));
        return -1;
    }
    return 0;
}

/*
 * Worker thread: main event loop
 */
static void *worker_thread(void *arg) {
    CQ_ITEM *item;
    NK_MEMCACHED_THREAD *me = arg;
    while (1) { // worker thread loop
        // wait for main thread's signal
        pthread_mutex_lock(&me->lock);
        while( (item = cq_pop(me->new_conn_queue)) == NULL){
            pthread_cond_wait(&me->cond, &me->lock);
        }
        pthread_mutex_unlock(&me->lock);
        fprintf(stderr, "worker %p wakes up for sfd %d\n", me, item->sfd);
/*
        CQ_ITEM *item = cq_pop(me->new_conn_queue);
        if(item == NULL) { 
            printf("worker is waken up but no conn in queue!!\n");
            continue;
        }
*/
        conn *c = conn_new(item->sfd, item->read_buffer_size);

        // handle this connection until it's closed
        drive_machine(c);
        cqi_free(item);
    } // worker thread loop
    return NULL;
}


/* Which thread we assigned a connection to most recently. */
static int memcached_last_thread = -1;

/*
 * Dispatches a new connection to another thread. This is only ever called
 * from the main thread, either during initialization (for UDP) or because
 * of an incoming connection.
 */
void dispatch_conn_new(int sfd, int read_buffer_size) { 
    CQ_ITEM *item = cqi_new();

    if (item == NULL) { 
        close(sfd);
        /* given that malloc failed this may also fail, but let's try */
        fprintf(stderr, "Failed to allocate memory for connection object\n");
        return;
    }

    memcached_last_thread = (memcached_last_thread + 1) % settings.num_threads;
    NK_MEMCACHED_THREAD *target_worker = threads + memcached_last_thread;

    item->sfd = sfd;
    item->read_buffer_size = read_buffer_size;

    fprintf(stderr, "wake up worker %p for sfd %d\n", target_worker, item->sfd);
    pthread_mutex_lock(&target_worker->lock);

    cq_push(target_worker->new_conn_queue, item);

    // signal target worker
    pthread_cond_signal(&target_worker->cond);
    pthread_mutex_unlock(&target_worker->lock);
}

/*
 * Re-dispatches a connection back to the original thread. Can be called from
 * any side thread borrowing a connection.
 */
void redispatch_conn(conn *c) {
}

/********************************* ITEM ACCESS *******************************/

/*
 * Allocates a new item.
 */
item *item_alloc(char *key, size_t nkey, int flags, rel_time_t exptime, int nbytes) {
    item *it;
    /* do_item_alloc handles its own locks */
    it = do_item_alloc(key, nkey, flags, exptime, nbytes);
    return it;
}

/*
 * Returns an item if it hasn't been marked as expired,
 * lazy-expiring as needed.
 */
item *item_get(const char *key, const size_t nkey, conn *c, const bool do_update) {
    item *it;
    uint32_t hv;
    hv = hash(key, nkey);
    item_lock(hv);
    it = do_item_get(key, nkey, hv, c, do_update);
    item_unlock(hv);
    return it;
}

// returns an item with the item lock held.
// lock will still be held even if return is NULL, allowing caller to replace
// an item atomically if desired.
item *item_get_locked(const char *key, const size_t nkey, conn *c, const bool do_update, uint32_t *hv) {
    item *it;
    *hv = hash(key, nkey);
    item_lock(*hv);
    it = do_item_get(key, nkey, *hv, c, do_update);
    return it;
}

item *item_touch(const char *key, size_t nkey, uint32_t exptime, conn *c) {
    item *it;
    uint32_t hv;
    hv = hash(key, nkey);
    item_lock(hv);
    it = do_item_touch(key, nkey, exptime, hv, c);
    item_unlock(hv);
    return it;
}

/*
 * Decrements the reference count on an item and adds it to the freelist if
 * needed.
 */
void item_remove(item *item) {
    uint32_t hv;
    hv = hash(ITEM_key(item), item->nkey);

    item_lock(hv);
    do_item_remove(item);
    item_unlock(hv);
}

/*
 * Replaces one item with another in the hashtable.
 * Unprotected by a mutex lock since the core server does not require
 * it to be thread-safe.
 */
int item_replace(item *old_it, item *new_it, const uint32_t hv) {
    return do_item_replace(old_it, new_it, hv);
}

/*
 * Stores an item in the cache (high level, obeys set/add/replace semantics)
 */
enum store_item_type store_item(item *item, int comm, conn* c) {
    enum store_item_type ret;
    uint32_t hv;

    hv = hash(ITEM_key(item), item->nkey);
    item_lock(hv);
    ret = do_store_item(item, comm, c, hv);
    item_unlock(hv);
    return ret;
}

int memcached_thread_init(int nthreads, void *arg) {
    int i;
    int power;

    for (i = 0; i < POWER_LARGEST; i++) {
        pthread_mutex_init(&lru_locks[i], NULL);
    }
    pthread_mutex_init(&worker_hang_lock, NULL);

    pthread_mutex_init(&cqi_freelist_lock, NULL);
    cqi_freelist = NULL;

    /* Want a wide lock table, but don't waste memory */
    if (nthreads < 3) {
        power = 10;
    } else if (nthreads < 4) {
        power = 11;
    } else if (nthreads < 5) {
        power = 12;
    } else if (nthreads <= 10) {
        power = 13;
    } else if (nthreads <= 20) {
        power = 14;
    } else {
        /* 32k buckets. just under the hashpower default. */
        power = 15;
    }

    if (power >= hashpower) {
        fprintf(stderr, "Hash table power size (%d) cannot be equal to or less than item lock table (%d)\n", hashpower, power);
        fprintf(stderr, "Item lock table grows with `-t N` (worker threadcount)\n");
        fprintf(stderr, "Hash table grows with `-o hashpower=N` \n");
        return -1;
    }

    item_lock_count = hashsize(power);
    item_lock_hashpower = power;

    item_locks = calloc(item_lock_count, sizeof(pthread_mutex_t));
    if (! item_locks) {
        printf("Can't allocate item locks");
        return -1;
    }

    threads = calloc(nthreads, sizeof(NK_MEMCACHED_THREAD));
    if (! threads) {
        printf("Can't allocate threads");
        return -1;
    }

    for (i = 0; i < nthreads; i++) {
        // init conn queue
        threads[i].new_conn_queue = malloc(sizeof(struct conn_queue));
        if (! threads[i].new_conn_queue) {
            printf("Can't allocate conn queues");
            return -1;
        }
        
        pthread_mutex_init(&threads[i].lock, NULL);
        pthread_cond_init(&threads[i].cond, NULL);

        cq_init(threads[i].new_conn_queue);

        // launch worker thread
        if(0 != create_worker(worker_thread, &threads[i]))
            return -1;
    }

    return 0;
}
