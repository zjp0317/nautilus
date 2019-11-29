/**
 * \file   test-malloc_test.c
 * \author C. Lever and D. Boreham, Christian Eder ( ederc@mathematik.uni-kl.de )
 * \date   2000
 * \brief  Test file for xmalloc. This is a multi-threaded test system by 
 *         Lever and Boreham. It is first noted in their paper "malloc() 
 *         Performance in a Multithreaded Linux Environment", appeared at the
 *         USENIX 2000 Annual Technical Conference: FREENIX Track.
 *         This file is part of XMALLOC, licensed under the GNU General
 *         Public License version 3. See COPYING for more information.
 */
#define _GNU_SOURCE
#include <nautilus/errno.h>
#include <nautilus/printk.h>
#include <nautilus/naut_types.h>
#include <nautilus/naut_string.h>
#include <nautilus/pthread.h>
#include <nautilus/shell.h>
//#include "xmalloc-config.h"
//#include "xmalloc.h"


#include "random.h"

#define printf(fmt, args...) nk_vc_printf(fmt, ##args)
#define fprintf(foo,fmt, args...) nk_vc_printf(fmt, ##args)

#define CACHE_ALIGNED 1

#define xmalloc malloc
#define xfree free

#define DEFAULT_OBJECT_SIZE 1024

static int debug_flag = 0;
static int verbose_flag = 0;
#define num_workers_default 4
static int num_workers = num_workers_default;
static double run_time = 5.0;
static int object_size = DEFAULT_OBJECT_SIZE;
/* array for thread ids */
static pthread_t *thread_ids;
/* array for saving result of each thread */
struct malloc_test_counter {
  long c
#if CACHE_ALIGNED
    __attribute__((aligned(64)))
#endif
;
};

static struct malloc_test_counter *counters;


static int done_flag = 0;
//struct timeval begin;
static double begin = 0.0;

/*
static void
tvsub(tdiff, t1, t0)
	struct timeval *tdiff, *t1, *t0;
{

	tdiff->tv_sec = t1->tv_sec - t0->tv_sec;
	tdiff->tv_usec = t1->tv_usec - t0->tv_usec;
	if (tdiff->tv_usec < 0)
		tdiff->tv_sec--, tdiff->tv_usec += 1000000;
}
*/
static double gettime() {
    // struct timeval t;
    //  gettimeofday(&t,NULL);
    //return (double)t.tv_sec+t.tv_usec*1e-6;

    return ((double)(nk_sched_get_realtime()))/1e9;
}

static
double elapsed_time(double *time0)
//double elapsed_time(struct timeval *time0)
{
	//struct timeval timedol;
	//struct timeval td;
	double et = 0.0;

	//gettimeofday(&timedol, (struct timezone *)0);
	//tvsub( &td, &timedol, time0 );
	//et = td.tv_sec + ((double)td.tv_usec) / 1000000;
    et = gettime() - *time0;

	return( et );
}

static const long possible_sizes[] = {8,12,16,24,32,48,64,96,128,192,256,(256*3)/2,512, (512*3)/2, 1024, (1024*3)/2, 2048};
static const int n_sizes = sizeof(possible_sizes)/sizeof(long);

#define OBJECTS_PER_BATCH 4096
struct batch {
  struct batch *next_batch;
  void *objects[OBJECTS_PER_BATCH];
};

static struct batch *batches = NULL;
static int batch_count = 0;
static const int batch_count_limit = 100;
static pthread_cond_t empty_cv; // = PTHREAD_COND_INITIALIZER;
static pthread_cond_t full_cv; // = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t lock; // = PTHREAD_MUTEX_INITIALIZER;

static
void enqueue_batch(struct batch *batch) {
  pthread_mutex_lock(&lock);
  struct lran2_st lr;
  while (batch_count >= batch_count_limit && !done_flag) {
    pthread_cond_wait(&full_cv, &lock);
  }
  batch->next_batch = batches;
  batches = batch;
  batch_count++;
  pthread_cond_signal(&empty_cv);
  pthread_mutex_unlock(&lock);
}

static
struct batch* dequeue_batch() {
  pthread_mutex_lock(&lock);
  while (batches == NULL && !done_flag) {
    pthread_cond_wait(&empty_cv, &lock);
  }
  struct batch* result = batches;
  if (result) {
    batches = result->next_batch;
    batch_count--;
    pthread_cond_signal(&full_cv);
  }
  pthread_mutex_unlock(&lock);
  return result;
}

#define atomic_load(addr) __atomic_load_n(addr, __ATOMIC_CONSUME)
#define atomic_store(addr, v) __atomic_store_n(addr, v, __ATOMIC_RELEASE)

static
void *mem_allocator (void *arg) {
  int thread_id = *(int *)arg;
  struct lran2_st lr;
  lran2_init(&lr, thread_id);

  while (!atomic_load(&done_flag)) {
    struct batch *b = xmalloc(sizeof(*b));
    if(b == NULL) {
        printf("zjp Insufficient memory!!");
        break;
    }
    for (int i = 0; i < OBJECTS_PER_BATCH; i++) {
      size_t siz = object_size > 0 ? object_size : possible_sizes[lran2(&lr)%n_sizes];
      b->objects[i] = xmalloc(siz);
      //memset(b->objects[i], i%256, siz);
    }
    enqueue_batch(b);
  }
  return NULL;
}

static
void *mem_releaser(void *arg) {
  int thread_id = *(int *)arg;

  while(!atomic_load(&done_flag)) {
    struct batch *b = dequeue_batch();
    if (b) {
      for (int i = 0; i < OBJECTS_PER_BATCH; i++) {
	xfree(b->objects[i]);
      }
      xfree(b);
    }
    counters[thread_id].c += OBJECTS_PER_BATCH;
  }
  return NULL;
}

static
int run_memory_free_test()
{
	void *ptr = NULL;
	int i;
	double elapse_time = 0.0;
	long total = 0;
	int *ids = (int *)xmalloc(sizeof(int) * num_workers);

	/* Initialize counter */
	for(i = 0; i < num_workers; ++i) 
		counters[i].c = 0;

	//gettimeofday(&begin, (struct timezone *)0);
    begin = gettime();

	/* Start up the mem_allocator and mem_releaser threads  */
	for(i = 0; i < num_workers; ++i) {
		ids[i] = i;
		if (verbose_flag) printf("Starting mem_releaser %i ...\n", i);
		if (pthread_create(&thread_ids[i * 2], NULL, mem_releaser, (void *)&ids[i])) {
			printk("ERROR pthread_create mem_releaser");
			//exit(errno);
            xfree(ids);
            return -1;
		}

		if (verbose_flag) printf("Starting mem_allocator %i ...\n", i);
		if (pthread_create(&thread_ids[i * 2 + 1], NULL, mem_allocator, (void *)&ids[i])) {
			printk("ERROR pthread_create mem_allocator");
			//exit(errno);
            xfree(ids);
            return -1;
		}
	}

	if (verbose_flag) printf("Testing for %.2f seconds\n\n", run_time);

	while (1) {
	  //usleep(1000);
      udelay(1000);
	  if (elapsed_time(&begin) > run_time) {
	    atomic_store(&done_flag, 1);
	    pthread_cond_broadcast(&empty_cv);
	    pthread_cond_broadcast(&full_cv);
	    break;
	  }
	}

	for(i = 0; i < num_workers * 2; ++i)
		pthread_join (thread_ids[i], &ptr);

	elapse_time = elapsed_time (&begin);

	for(i = 0; i < num_workers; ++i) {
		if (verbose_flag) {
			printf("Thread %2i frees %ld blocks in %.2f seconds. %.2f free/sec.\n",
			       i, counters[i].c, elapse_time, ((double)counters[i].c/elapse_time));
		}
	}
	if (verbose_flag) printf("----------------------------------------------------------------\n");
	for(i = 0; i < num_workers; ++i) total += counters[i].c;
	if (verbose_flag)
	  printf("Total %ld freed in %.2f seconds. %.2fM free/second\n",
		 total, elapse_time, ((double) total/elapse_time)*1e-6);
	else
	  printf("%.0f\n", (double)total/elapse_time);

	if (verbose_flag) printf("Program done\n");
	return(0);
}

static void usage(char *prog)
{
	printf("%s [-w workers] [-t run_time] [-d] [-v]\n", prog);
	printf("\t -w number of producer threads (and number of consumer threads), default %d\n", num_workers_default);
	printf("\t -t run time in seconds, default 20.0 seconds.\n");
	printf("\t -s size of object to allocate (default %d bytes) (specify -1 to get many different object sizes)\n", DEFAULT_OBJECT_SIZE);
	printf("\t -d debug mode\n");
	printf("\t -v verbose mode (-v -v produces more verbose)\n");
	//exit(1);
}

static int
handle_malloc_test (char * buf, void * priv)
{
    // zjp use init()
    pthread_cond_init(&empty_cv, NULL); 
    pthread_cond_init(&full_cv, NULL); 
    pthread_mutex_init(&lock, NULL); 
    done_flag = 0;

    // just use integers
    if (sscanf(buf, "malloc-test %u %u %d",&num_workers,&run_time,&object_size) != 3) {
        num_workers = num_workers_default;
        run_time = 5.0;
        object_size = DEFAULT_OBJECT_SIZE;
        printf("Use default setting: workers %d runtime %lf object size %d\n", num_workers, run_time,object_size);
        //return 0;
    } else {
        printf("Use setting: workers %d runtime %lf object size %d\n", num_workers, run_time,object_size);
    }

    // always verbose
    verbose_flag++;
/*
	int c;
	while ((c = getopt(argc, argv, "w:t:ds:v")) != -1) {
		
		switch (c) {

		case 'w':
			num_workers = atoi(optarg);
			break;
		case 't':
			run_time = atof(optarg);
			break;
		case 'd':
			debug_flag = 1;
			break;
		case 's':
			object_size = atoi(optarg);
			break;
		case 'v':
			verbose_flag++;
			break;
		default:
			usage(argv[0]);
		}
	}
*/
	/* allocate memory for working arrays */
	thread_ids = (pthread_t *) xmalloc(sizeof(pthread_t) * num_workers * 2);
	counters = (struct malloc_test_counter *) xmalloc(sizeof(*counters) * num_workers);
	
	//run_memory_free_test();
    if(run_memory_free_test() != 0) {
        xfree(thread_ids);
        xfree(counters);
        return -1;
    }
	while (batches) {
	  struct batch *b = batches;
	  batches = b->next_batch;
	  for (int i = 0 ; i < OBJECTS_PER_BATCH; i++) {
	    xfree(b->objects[i]);
	  }
	  xfree(b);
	}
	return 0;
}

static struct shell_cmd_impl malloc_test_impl = {
    .cmd      = "malloc-test",
    .help_str = "malloc-test [workers-threads] [run-time] [obj-size]",
    .handler  = handle_malloc_test,
};
nk_register_shell_cmd(malloc_test_impl);
