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

#define printf(fmt, args...) nk_vc_printf(fmt, ##args)
#define fprintf(foo,fmt, args...) nk_vc_printf(fmt, ##args)

#define calloc(n,s) ({ void *_p=mallocz(n*s); _p; })
//#define calloc(n,s) ({ void *_p=malloc(n*s); memset(_p,0,n*s); _p; })

#define MAX_SET (8*1024ul*1024ul)

#define START_PSIZE 2 // 128

uint64_t MAX_PSIZE = 0; // in KB
//#define MAX_PSIZE (4*1024ul) //(1024ul*1024ul*1024ul)
//#define MAX_PSIZE (1024ul*1024ul*64ul) //(1024ul*1024ul*1024ul)

static double gettime() {
    //struct timeval t;
    //gettimeofday(&t,NULL);
    //return (double)t.tv_sec+t.tv_usec*1e-6;
#ifdef NAUT_CONFIG_PISCES
    return nk_sched_get_realtime_secs();
#endif
    return ((double)(nk_sched_get_realtime()))/1e9;
}

//int main(int argc, char *argv[] __attribute__((unused))) {
static int
handle_calloc_test (char * buf, void * priv)
{
    int ret = 0;
    if ((ret = sscanf(buf, "calloc-test %lu",&MAX_PSIZE)) != 1) {
        MAX_PSIZE = 1*1024;
        printf("Use default setting:  MAX_PSIZE %lu\n", MAX_PSIZE);
    } else {
        MAX_PSIZE *= 1024;
        printf("Use setting:  MAX_PSIZE %lu\n", MAX_PSIZE);
    }

    double begin = gettime();
    double mtime = 0.0;
    double ctime = 0.0;
    double ftime = 0.0;
    size_t counter = 0;
    //assert(argc == 1);
    size_t max_set = MAX_SET;// 8*1024*1024;
    for (size_t psize = START_PSIZE; psize <= MAX_PSIZE; psize *= 2) {
        for (size_t size = psize; size < 2*psize; size += psize/1024 + 1) {
        //for (size_t psize = 128; psize <= 1024ul*1024ul*1024ul; psize *= 2) {
        //for (size_t size = psize; size < 2*psize; size += psize/8) {
            double tmp = gettime();
            char *p = malloc(size);
            tmp = gettime() - tmp;
            //printf("malloc time = %lf\n", tmp);
            mtime += tmp;

            if(!p) {
                printf("ERROR malloc for size %lu is NULL\n", size);
                return 0;
            }
            for (size_t i = 0; i < size && i < max_set; i+=64) p[i] = i;

            tmp = gettime();
            free(p);
            tmp = gettime() - tmp;
            ftime += tmp;

#if 0
            tmp = gettime();
            char *q = calloc(size, 1);
            tmp = gettime() - tmp;
            //printf("calloc time = %lf\n", tmp);
            ctime += tmp;

            if(!p) {
                printf("ERROR calloc for size %lu*1 is NULL\n", size);
                return 0;
            }
            if (0) {
                // This assertion is not always true, and I think that's OK.
                if (p!=q) printf("Did %p=malloc(%ld) then free(%p), then %p=calloc(%ld, 1)\n", p, size, p, q, size);
                //assert(p == q);
            }
            //for (size_t i = 0; i < size && i < max_set; i+=64) assert(q[i] == 0);
            for (size_t i = 0; i < size && i < max_set; i+=64) q[i] = i;

            tmp = gettime();
            free(q);
            tmp = gettime() - tmp;
            ftime += tmp;

            tmp = gettime();
            char *r = calloc(1, size);
            tmp = gettime() - tmp;
            //printf("--calloc time = %lf\n", tmp);
            ctime += tmp;

            if(!p) {
                printf("ERROR calloc for size 1*%lu is NULL\n", size);
                return 0;
            }
            //for (size_t i = 0; i < size && i < max_set; i+=64) assert(r[i] == 0);
            for (size_t i = 0; i < size && i < max_set; i+=64) r[i] = i;

            tmp = gettime();
            free(r);
            tmp = gettime() - tmp;
            ftime += tmp;
#endif

            counter++;
        }
    }
    printf("time = %lf\n malloc(%lu) time = %lf\n calloc(%lu) time = %lf\n free(%lu) time = %lf\n", gettime() - begin, counter, mtime, counter*2, ctime, counter*3, ftime);
    return 0;
}

static struct shell_cmd_impl calloc_test_impl = {
    .cmd      = "calloc-test",
    .help_str = "calloc-test", 
    .handler  = handle_calloc_test,
};
nk_register_shell_cmd(calloc_test_impl);
