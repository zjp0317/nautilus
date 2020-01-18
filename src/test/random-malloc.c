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

#define RUNS 300 

#define SEED 23

#define GAP //{udelay(100000);} 

#define MAX_ORDER 27
#define MIN_ORDER 12
#define MAX_NUM_PER_ORDER 10

int counter[MAX_ORDER+1] = {0};
char* p[MAX_ORDER+1][MAX_NUM_PER_ORDER]={NULL};

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

    srand48(SEED);
    size_t begin = gettime();
    size_t mtime = 0.0;
    size_t ftime = 0.0;
    size_t i, j;
    size_t failed = 0;
    size_t runs = RUNS;//MAX_MEM / max_alloc_size;
    if(runs == 0) {
        INFO_PRINT("test runs less than 1. Use small unit\n");
        return 0 ;
    }

    for(i = 0; i < runs; i++) {
        size_t tmp = gettime();
        if((lrand48() & 0x1) == 0) {
            size_t order = (lrand48() % MAX_ORDER) + 1;
            if(order < MIN_ORDER)
                order = MIN_ORDER;
            if(counter[order] > MAX_NUM_PER_ORDER) {
                for(j = MIN_ORDER; j <= MAX_ORDER; j++) {
                    if(counter[j] < MAX_NUM_PER_ORDER) {
                        order = j;
                        break;
                    }
                }
                if(j > MAX_ORDER) {
                    continue;
                }
            }
            for(j = 0; j < MAX_NUM_PER_ORDER; j++) {
                if(p[order][j] == NULL) {
                    p[order][j]= malloc(1UL<<order);
                    break;
                }
            }
            counter[order]++;
        } else {
            size_t order = (lrand48() % MAX_ORDER) + 1;
            if(order < MIN_ORDER)
                order = MIN_ORDER;
            if(counter[order] == 0) {
                for(j = MIN_ORDER; j <= MAX_ORDER; j++) {
                    if(counter[j] > 0) {
                        order = j;
                        break;
                    }
                }
            }
            for(j = 0; j < MAX_NUM_PER_ORDER; j++) {
                if(p[order][j] != NULL) {
                    free(p[order][j]);
                    p[order][j] = NULL;
                    break;
                }
            }
            counter[order]--;
        }
        mtime += gettime() - tmp;
        GAP;
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

INFO_PRINT("time = %lu\n malloc(%lu) time = %lu\n free(%lu) time = %lu\n faled = %lu\n", gettime() - begin, runs, mtime, runs, ftime, failed);
return 0;
}

static struct shell_cmd_impl malloc_test1_impl = {
.cmd      = "random-malloc",
.help_str = "random-malloc", 
.handler  = handle_malloc_test1,
};
nk_register_shell_cmd(malloc_test1_impl);
