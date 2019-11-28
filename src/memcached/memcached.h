/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/** \file
 * The main memcached header holding commonly used data
 * structures and function prototypes.
 */
#ifndef __NAUT_MEMCACHED_H__
#define __NAUT_MEMCACHED_H__

#ifdef __Nautilus__
#include <nautilus/nautilus.h>
#include <nautilus/naut_types.h>
#include <nautilus/naut_assert.h>
#include <nautilus/errno.h>
#include <nautilus/timer.h>

#include <nautilus/pthread.h>
 
#include <lwip/sockets.h>
#include <lwip/errno.h>

#include "trace.h"
#include "protocol_binary.h"

typedef unsigned char bool;
typedef sint64_t int64_t;
typedef sint32_t int32_t;
typedef sint8_t int8_t;

typedef long unsigned int caddr_t;

#define assert ASSERT

#define calloc(n,s) ({ void *_p=mallocz(n*s); _p; })

#define printf(fmt, args...) nk_vc_printf(fmt, ##args);
#define fprintf(foo,fmt, args...) nk_vc_printf(fmt, ##args);

#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "trace.h"
#include "protocol_binary.h"

#include <stdbool.h>

/* unistd.h is here */
# include <unistd.h>
#endif

typedef unsigned int rel_time_t;

#define ENDIAN_LITTLE 1

/** Maximum length of a key. */
#define KEY_MAX_LENGTH 250

/** Maximum length of a uri encoded key. */
#define KEY_MAX_URI_ENCODED_LENGTH (KEY_MAX_LENGTH  * 3 + 1)

/** Size of an incr buf. */
#define INCR_MAX_STORAGE_LEN 24

#define DATA_BUFFER_SIZE 2048
#define UDP_READ_BUFFER_SIZE 65536
#define UDP_MAX_PAYLOAD_SIZE 1400
#define UDP_HEADER_SIZE 8
#define MAX_SENDBUF_SIZE (256 * 1024 * 1024)
/* Up to 3 numbers (2 32bit, 1 64bit), spaces, newlines, null 0 */
#define SUFFIX_SIZE 50

/** Initial size of list of items being returned by "get". */
#define ITEM_LIST_INITIAL 200

/** Initial size of list of CAS suffixes appended to "gets" lines. */
#define SUFFIX_LIST_INITIAL 100

/** Initial size of the sendmsg() scatter/gather array. */
#define IOV_LIST_INITIAL 400

/** Initial number of sendmsg() argument structures to allocate. */
#define MSG_LIST_INITIAL 10

/** High water marks for buffer shrinking */
#define READ_BUFFER_HIGHWAT 8192
#define ITEM_LIST_HIGHWAT 400
#define IOV_LIST_HIGHWAT 600
#define MSG_LIST_HIGHWAT 100

/* Binary protocol stuff */
#define MIN_BIN_PKT_LENGTH 16
#define BIN_PKT_HDR_WORDS (MIN_BIN_PKT_LENGTH/sizeof(uint32_t))

/* Initial power multiplier for the hash table */
#define HASHPOWER_DEFAULT 16
#define HASHPOWER_MAX 32

/*
 * We only reposition items in the LRU queue if they haven't been repositioned
 * in this many seconds. That saves us from churning on frequently-accessed
 * items.
 */
#define ITEM_UPDATE_INTERVAL 60



/* Slab sizing definitions. */
#define POWER_SMALLEST 1
#define POWER_LARGEST  256 /* actual cap is 255 */
#define SLAB_GLOBAL_PAGE_POOL 0 /* magic slab class for storing pages for reassignment */
#define CHUNK_ALIGN_BYTES 8
/* slab class max is a 6-bit number, -1. */
#define MAX_NUMBER_OF_SLAB_CLASSES (63 + 1)

/** How long an object can reasonably be assumed to be locked before
    harvesting it on a low memory condition. Default: disabled. */
#define TAIL_REPAIR_TIME_DEFAULT 0

/* warning: don't use these macros with a function, as it evals its arg twice */
#define ITEM_get_cas(i) (((i)->it_flags & ITEM_CAS) ? \
        (i)->data->cas : (uint64_t)0)

#define ITEM_set_cas(i,v) { \
    if ((i)->it_flags & ITEM_CAS) { \
        (i)->data->cas = v; \
    } \
}

#define ITEM_key(item) (((char*)&((item)->data)) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

#define ITEM_suffix(item) ((char*) &((item)->data) + (item)->nkey + 1 \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

#define ITEM_data(item) ((char*) &((item)->data) + (item)->nkey + 1 \
         + (((item)->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

#define ITEM_ntotal(item) (sizeof(struct _stritem) + (item)->nkey + 1 \
         + (item)->nbytes \
         + (((item)->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

#define ITEM_clsid(item) ((item)->slabs_clsid & ~(3<<6))


/** Item client flag conversion */
#define FLAGS_CONV(it, flag) { \
    if ((it)->it_flags & ITEM_CFLAGS) { \
        flag = *((uint32_t *)ITEM_suffix((it))); \
    } else { \
        flag = 0; \
    } \
}

#define FLAGS_SIZE(item) (((item)->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0)

#define NREAD_ADD 1
#define NREAD_SET 2
#define NREAD_REPLACE 3
#define NREAD_APPEND 4
#define NREAD_PREPEND 5
#define NREAD_CAS 6

struct settings {
    size_t maxbytes;
    int maxconns;
    int port;
    int verbose;

    rel_time_t oldest_live; /* ignore existing items older than this */
    uint64_t oldest_cas; /* ignore existing items with CAS values lower than this */

    int num_threads;        /* number of worker (without dispatcher) libevent threads to run */
    double factor;          /* chunk size growth factor */
    int chunk_size;
    int hashpower_init;     /* Starting hash power level */

    bool use_cas;
    int item_size_max;        /* Maximum item size */
    int slab_chunk_size_max;  /* Upper end for chunks within slab pages. */
    int slab_page_size;     /* Slab's page units. */

    bool slab_reassign;     /* Whether or not slab reassignment is allowed */

    char *hash_algorithm;     /* Hash algorithm in use */
};

extern struct settings settings;

enum store_item_type {
    NOT_STORED=0, STORED, EXISTS, NOT_FOUND, TOO_LARGE, NO_MEMORY
};

enum delta_result_type {
    OK, NON_NUMERIC, EOM, DELTA_ITEM_NOT_FOUND, DELTA_ITEM_CAS_MISMATCH
};

extern time_t process_started;

#define ITEM_LINKED 1
#define ITEM_CAS 2

/* temp */
#define ITEM_SLABBED 4

/* Item was fetched at least once in its lifetime */
#define ITEM_FETCHED 8
/* Appended on fetch, removed on LRU shuffling */
#define ITEM_ACTIVE 16
/* If an item's storage are chained chunks. */
#define ITEM_CHUNKED 32
#define ITEM_CHUNK 64
/* ITEM_data bulk is external to item */
#define ITEM_HDR 128
/* additional 4 bytes for item client flags */
#define ITEM_CFLAGS 256
/* item has sent out a token already */
#define ITEM_TOKEN_SENT 512
/* reserved, in case tokens should be a 2-bit count in future */
#define ITEM_TOKEN_RESERVED 1024
/* if item has been marked as a stale value */
#define ITEM_STALE 2048

/**
 * Structure for storing items within memcached.
 */
typedef struct _stritem {
    /* Protected by LRU locks */
    struct _stritem *next;
    struct _stritem *prev;
    /* Rest are protected by an item lock */
    struct _stritem *h_next;    /* hash chain next */
    rel_time_t      time;       /* least recent access */
    rel_time_t      exptime;    /* expire time */
    int             nbytes;     /* size of data */
    unsigned short  refcount;
    uint16_t        it_flags;   /* ITEM_* above */
    uint8_t         slabs_clsid;/* which slab class we're in */
    uint8_t         nkey;       /* key length, w/terminating null and padding */
    /* this odd type prevents type-punning issues when we do
     * the little shuffle to save space when not using CAS. */
    union {
        uint64_t cas;
        char end;
    } data[];
    /* if it_flags & ITEM_CAS we have 8 bytes CAS */
    /* then null-terminated key */
    /* then " flags length\r\n" (no terminating null) */
    /* then data with terminating \r\n (no terminating null; it's binary!) */
} item;


/* Header when an item is actually a chunk of another item. */
typedef struct _strchunk {
    struct _strchunk *next;     /* points within its own chain. */
    struct _strchunk *prev;     /* can potentially point to the head. */
    struct _stritem  *head;     /* always points to the owner chunk */
    int              size;      /* available chunk space in bytes */
    int              used;      /* chunk space used */
    int              nbytes;    /* used. */
    unsigned short   refcount;  /* used? */
    uint16_t         it_flags;  /* ITEM_* above. */
    uint8_t          slabs_clsid; /* Same as above. */
    uint8_t          orig_clsid; /* For obj hdr chunks slabs_clsid is fake. */
    char data[];
} item_chunk;

#ifdef NEED_ALIGN
static inline char *ITEM_schunk(item *it) {
    int offset = it->nkey + 1
        + ((it->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0)
        + ((it->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0);
    int remain = offset % 8;
    if (remain != 0) {
        offset += 8 - remain;
    }
    return ((char *) &(it->data)) + offset;
}
#else
#define ITEM_schunk(item) ((char*) &((item)->data) + (item)->nkey + 1 \
         + (((item)->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))
#endif

typedef struct {
    pthread_t thread_id;        /* unique ID of this thread */
    struct conn_queue *new_conn_queue; /* queue of new connections to handle */

    pthread_mutex_t lock;  
    pthread_cond_t cond;        /* sync with main */
} NK_MEMCACHED_THREAD;
typedef struct conn conn;
/**
 * The structure representing a connection into memcached.
 */
struct conn {
    int    sfd;
    bool set_stale;

    char   *rbuf;   /** buffer to read commands into */
    char   *rcurr;  /** but if we parsed some already, this is where we stopped */
    int    rsize;   /** total allocated size of rbuf */
    int    rbytes;  /** how much data, starting from rcur, do we have unparsed */

    char   *wbuf;
    int    wsize;

    char   *ritem;  /** when we read in an item's value, it goes here */

    /* data for the nread state */

    /**
     * item is used to hold an item structure created after reading the command
     * line of set/add/replace commands, but before we finished reading the actual
     * data. The data is read into ITEM_data(item) to avoid extra copying.
     */

    void   *item;     /* for commands set/add/replace  */

    /* data for the mwrite state */
    struct iovec *iov;
    int    iovsize;   /* number of elements allocated in iov[] */
    int    iovused;   /* number of elements used in iov[] */

    struct msghdr *msglist;
    int    msgsize;   /* number of elements allocated in msglist[] */
    int    msgused;   /* number of elements used in msglist[] */
    int    msgcurr;   /* element in msglist[] being transmitted now */
    int    msgbytes;  /* number of bytes in current msg */

    /* data for UDP clients */
#ifdef __Nautilus__
    struct sockaddr_in request_addr; /* udp: Who sent the most recent request */
#else
    struct sockaddr_in6 request_addr; /* udp: Who sent the most recent request */
#endif
    socklen_t request_addr_size;

    /* Binary protocol stuff */
    /* This is where the binary header goes */
    protocol_binary_request_header binary_header;
    uint64_t cas; /* the cas to return */
    short cmd; /* current command being processed */
    int opaque;
    int keylen;
    conn   *next;     /* Used for generating a list of conn structures */
    NK_MEMCACHED_THREAD *thread; /* Pointer to the thread object serving this connection */
#ifdef __Nautilus__
    ssize_t (*nk_read)(conn  *c, void *buf, size_t count);
    ssize_t (*nk_sendmsg)(conn *c, struct msghdr *msg, int flags);
    ssize_t (*nk_write)(conn *c, void *buf, size_t count);
#else
    ssize_t (*read)(conn  *c, void *buf, size_t count);
    ssize_t (*sendmsg)(conn *c, struct msghdr *msg, int flags);
    ssize_t (*write)(conn *c, void *buf, size_t count);
#endif
};

/* array of conn structures, indexed by file descriptor */
extern conn **conns;

/* current time of day (updated periodically) */
//extern volatile rel_time_t current_time;
#define current_time (time(NULL))

/* TODO: Move to slabs.h? */
extern volatile int slab_rebalance_signal;

struct slab_rebalance {
    void *slab_start;
    void *slab_end;
    void *slab_pos;
    int s_clsid;
    int d_clsid;
    uint32_t busy_items;
    uint32_t rescues;
    uint32_t evictions_nomem;
    uint32_t inline_reclaim;
    uint32_t chunk_rescues;
    uint32_t busy_deletes;
    uint32_t busy_loops;
    uint8_t done;
};

extern struct slab_rebalance slab_rebal;
/*
 * Functions
 */
enum delta_result_type do_add_delta(conn *c, const char *key,
                                    const size_t nkey, const bool incr,
                                    const int64_t delta, char *buf,
                                    uint64_t *cas, const uint32_t hv);
enum store_item_type do_store_item(item *item, int comm, conn* c, const uint32_t hv);
conn *conn_new(const int sfd, int read_buffer_size) ;

#define mutex_lock(x) pthread_mutex_lock(x)
#define mutex_unlock(x) pthread_mutex_unlock(x)

#include "slabs.h"
#include "assoc.h"
#include "items.h"
#include "hash.h"
#include "util.h"

/*
 * Functions such as the libevent-related calls that need to do cross-thread
 * communication in multithreaded mode (rather than actually doing the work
 * in the current thread) are called via "dispatch_" frontends, which are
 * also #define-d to directly call the underlying code in singlethreaded mode.
 */
void drive_machine(conn *c);

int memcached_thread_init(int nthreads, void *arg);
void redispatch_conn(conn *c);
void dispatch_conn_new(int sfd, int read_buffer_size);

/* Lock wrappers for cache functions that are called from main loop. */
enum delta_result_type add_delta(conn *c, const char *key,
                                 const size_t nkey, bool incr,
                                 const int64_t delta, char *buf,
                                 uint64_t *cas);
item *item_alloc(char *key, size_t nkey, int flags, rel_time_t exptime, int nbytes);
#define DO_UPDATE true
#define DONT_UPDATE false
item *item_get(const char *key, const size_t nkey, conn *c, const bool do_update);
item *item_get_locked(const char *key, const size_t nkey, conn *c, const bool do_update, uint32_t *hv);
item *item_touch(const char *key, const size_t nkey, uint32_t exptime, conn *c);
void  item_remove(item *it);
int   item_replace(item *it, item *new_it, const uint32_t hv);

void item_lock(uint32_t hv);
void *item_trylock(uint32_t hv);
void item_trylock_unlock(void *arg);
void item_unlock(uint32_t hv);
void stop_threads(void);
int stop_conn_timeout_thread(void);
#define refcount_incr(it) ++(it->refcount)
#define refcount_decr(it) --(it->refcount)

/* Stat processing functions */

enum store_item_type store_item(item *item, int comm, conn *c);

#define setup_privilege_violations_handler()
#define drop_privileges()

#define drop_worker_privileges()

#ifndef __Nautilus__
/* If supported, give compiler hints for branch prediction. */
#if !defined(__GNUC__) || (__GNUC__ == 2 && __GNUC_MINOR__ < 96)
#define __builtin_expect(x, expected_value) (x)
#endif

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#endif

#endif
