//#include <assert.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <sys/time.h>
//#include "supermalloc.h"

#include <nautilus/nautilus.h>
#include <nautilus/errno.h>
#include <nautilus/printk.h>
#include <nautilus/naut_types.h>
#include <nautilus/naut_string.h>
#include <nautilus/thread.h>
#include <nautilus/shell.h>

#define INFO_PRINT(fmt, args...) nk_vc_printf(fmt, ##args)
#define fINFO_PRINT(foo,fmt, args...) nk_vc_printf(fmt, ##args)

static uint64_t max_alloc_size = 0; // in KB

#define MAX_MEM (512*1024UL*1024UL) // 512M
#define RUNS 300 

#define SEED 23

#define GAP //{udelay(100000);} 

//#define max_alloc_size (4*1024ul) //(1024ul*1024ul*1024ul)
//#define max_alloc_size (1024ul*1024ul*64ul) //(1024ul*1024ul*1024ul)

static size_t gettime() {
    //struct timeval t;
    //gettimeofday(&t,NULL);
    //return (size_t)t.tv_sec+t.tv_usec*1e-6;
#ifdef NAUT_CONFIG_PISCES
    return rdtsc();
    //return nk_sched_get_realtime_secs();
#endif
    return ((size_t)(nk_sched_get_realtime()))/1e9;
}

//int main(int argc, char *argv[] __attribute__((unused))) {
static int
handle_malloc_test1 (char * buf, void * priv)
{

    int ret = 0;
    long  shift = 1;
    if ((ret = sscanf(buf, "malloc-test1 %lu %ld",&max_alloc_size, &shift)) != 2) {
        max_alloc_size = 4*1024;
        shift = 10;
        INFO_PRINT("Use default setting:  max_alloc_size %lu\n", max_alloc_size);
    } else {
        max_alloc_size *= 4*1024;
        INFO_PRINT("Use setting:  max_alloc_size %lu\n", max_alloc_size);
    }

    srand48(SEED);
    size_t begin = gettime();
    size_t mtime = 0.0;
    size_t ftime = 0.0;
    size_t i = 0;
    size_t failed = 0;
    size_t runs = RUNS;//MAX_MEM / max_alloc_size;
    if(runs == 0) {
        INFO_PRINT("test runs less than 1. Use small unit\n");
        return 0 ;
    }

    char **p = (char**)malloc(runs * sizeof(char*));

    for(i = 0; i < runs; i++) {
        size_t tmp = gettime();
        p[i] = malloc(max_alloc_size >> (lrand48() % shift));
        if(p[i] == NULL) {
            INFO_PRINT("failed allocation at runs %d\n", i);
            failed++;
        }
        mtime += gettime() - tmp;
        GAP;
    }
    for(i = 0; i < runs; i++) {
        if(p[i] == NULL)
            continue;
        size_t tmp = gettime();
        free(p[i]);
        ftime += gettime() - tmp;
    }
#if 0
    INFO_PRINT("************************\n");
    /***********/
    for(i = 0; i < runs; i++) {
        size_t tmp = gettime();
        p[i] = malloc(max_alloc_size >> (lrand48() % 5));
        if(p[i] == NULL) {
            INFO_PRINT("failed allocation at runs %d\n", i);
            failed++;
        }
        mtime += gettime() - tmp;
        GAP;
    }
    for(i = 0; i < runs; i++) {
        if(p[i] == NULL)
            continue;
        size_t tmp = gettime();
        free(p[i]);
        ftime += gettime() - tmp;
    }
    /***********/
    INFO_PRINT("************************\n");
    for(i = 0; i < runs; i++) {
        size_t tmp = gettime();
        p[i] = malloc(max_alloc_size >> (lrand48() % 10));
        if(p[i] == NULL) {
            INFO_PRINT("failed allocation at runs %d\n", i);
            failed++;
        }
        mtime += gettime() - tmp;
        GAP;
    }
    for(i = 0; i < runs; i++) {
        if(p[i] == NULL)
            continue;
        size_t tmp = gettime();
        free(p[i]);
        ftime += gettime() - tmp;
    }
    runs *= 3;
#endif

    free(p);
    INFO_PRINT("time = %lu\n malloc(%lu) time = %lu\n free(%lu) time = %lu\n faled = %lu\n", gettime() - begin, runs, mtime, runs, ftime, failed);
    return 0;
}

static struct shell_cmd_impl malloc_test1_impl = {
    .cmd      = "malloc-test1",
    .help_str = "malloc-test1", 
    .handler  = handle_malloc_test1,
};
nk_register_shell_cmd(malloc_test1_impl);
