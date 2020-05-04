/* sh6bench.c -- SmartHeap (tm) Portable memory management benchmark.
 *
 * Copyright (C) 2000 MicroQuill Software Publishing Corporation.
 * All Rights Reserved.
 *
 * No part of this source code may be copied, modified or reproduced
 * in any form without retaining the above copyright notice.
 * This source code, or source code derived from it, may not be redistributed
 * without express written permission of the copyright owner.
 *
 *
 * Compile-time flags.  Define the following flags on the compiler command-line
 * to include the selected APIs in the benchmark.  When testing an ANSI C
 * compiler, include MALLOC_ONLY flag to avoid any SmartHeap API calls.
 * Define these symbols with the macro definition syntax for your compiler,
 * e.g. -DMALLOC_ONLY=1 or -d MALLOC_ONLY=1
 *
 *  Flag                   Meaning
 *  -----------------------------------------------------------------------
 *  MuALLOC_ONLY=1       Test ANSI malloc/realloc/free only
 *  INCLUDE_NEW=1       Test C++ new/delete
 *  INCLUDE_MOVEABLE=1  Test SmartHeap handle-based allocation API
 *  MIXED_ONLY=1        Test interdispersed alloc/realloc/free only
 *                      (no tests for alloc, realloc, free individually)
 *  SYS_MULTI_THREAD=1  Test with multiple threads (OS/2, NT, HP, Solaris only)
 *  SMARTHEAP=1         Required when compiling if linking with SmartHeap lib
 * 
 *
 */

#include <nautilus/nautilus.h>
#include <nautilus/naut_types.h>
#include <nautilus/naut_assert.h>
#include <nautilus/naut_string.h>
#include <nautilus/errno.h>
#include <nautilus/timer.h>
#include <nautilus/shell.h>
#include <nautilus/vc.h>
#include <nautilus/pthread.h>

#define SYS_MULTI_THREAD 1

#define printf(fmt, args...) nk_vc_printf(fmt, ##args)
#define fprintf(foo,fmt, args...) nk_vc_printf(fmt, ##args)

#ifdef __cplusplus
extern "C"
{
#endif

#define UNIX 1
#ifdef SYS_MULTI_THREAD
typedef pthread_t ThreadID;
ThreadID ThreadNULL = {0, 0, 0};
//#define THREAD_NULL ThreadNULL
//#define THREAD_EQ(a,b) pthread_equal(a,b)
#endif /* end of environment-specific header files */

#ifndef THREAD_NULL
#define THREAD_NULL 0
#endif
#ifndef THREAD_EQ
#define THREAD_EQ(a,b) ((a)==(b))
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

/* Note: the SmartHeap header files must be included _after_ any files that
 * declare malloc et al
 */
//#include "smrtheap.h"
#ifdef MALLOC_ONLY
#undef malloc
#undef realloc
#undef free
#endif

#ifdef SILENT
void fprintf_silent(FILE *, ...);
void fprintf_silent(FILE *x, ...) { (void)x; }
#else
#define fprintf_silent fprintf
#endif

#ifndef min
#define min(a,b)    (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a,b)    (((a) > (b)) ? (a) : (b))
#endif

#ifdef CLK_TCK
#undef CLK_TCK
#endif
#define CLK_TCK CLOCKS_PER_SEC

#define TRUE 1
#define FALSE 0
typedef int Bool;

//FILE *stderr, *fin;
unsigned uMaxBlockSize = 1000;
unsigned uMinBlockSize = 1;
unsigned long ulCallCount = 1000;

unsigned long promptAndRead(char *msg, unsigned long defaultVal, char fmtCh);

#ifdef SYS_MULTI_THREAD
unsigned uThreadCount = 8;
ThreadID RunThread(void (*fn)(void *), void *arg);
void WaitForThreads(ThreadID[], unsigned);
int GetNumProcessors(void);
#else
unsigned uThreadCount = 1;
#endif

#ifdef HEAPALLOC_WRAPPER
#define TEST_HEAPALLOC 1
#endif

#ifdef TEST_HEAPALLOC
#ifdef malloc
#undef malloc
#undef realloc
#undef free
#endif

#define malloc(s) HeapAlloc(GetProcessHeap(), 0, s)
#define realloc(p, s) HeapReAlloc(GetProcessHeap(), 0, p, s)
#define free(p) HeapFree(GetProcessHeap(), 0, p)

#endif

void doBench(void *);

//void main(int argc, char *argv[])
//{
static int
handle_shbench (char * buf, void * priv)
{
    int ret = 0;

	//clock_t startCPU;
	//time_t startTime;
	//double elapsedTime, cpuTime;
	uint64_t startCPU, startTime, elapsedTime, cpuTime;

    if ((ret = sscanf(buf, "shbench %d %d %d ", 
                    &ulCallCount, &uMinBlockSize, &uMaxBlockSize )) != 3) {
    }
/*
	ulCallCount = promptAndRead("call count", ulCallCount, 'u');
	uMinBlockSize = (unsigned)promptAndRead("min block size",uMinBlockSize,'u');
	uMaxBlockSize = (unsigned)promptAndRead("max block size",uMaxBlockSize,'u');
*/
#ifdef HEAPALLOC_WRAPPER
	LoadLibrary("shsmpsys.dll");
#endif
	
#ifdef SYS_MULTI_THREAD
	{
		unsigned i;
		void *threadArg = NULL;
		ThreadID *tids;

		uThreadCount = nautilus_info.sys.num_cpus;//(int)promptAndRead("threads", GetNumProcessors(), 'u');

		if (uThreadCount < 1)
			uThreadCount = 1;
		ulCallCount /= uThreadCount;
		if ((tids = malloc(sizeof(ThreadID) * uThreadCount)) != NULL)
		{
			startCPU = rdtscp();//clock();
			startTime = time(NULL);
			for (i = 0;  i < uThreadCount;  i++)
				if (THREAD_EQ(tids[i] = RunThread(doBench, threadArg),THREAD_NULL))
				{
					fprintf(stderr, "\nfailed to start thread #%d", i);
					break;
				}

			WaitForThreads(tids, uThreadCount);
			free(tids);
		}
		if (threadArg)
			free(threadArg);
	}
#else
	startCPU = rdtscp();//clock();
	startTime = rdtscp(); //time(NULL);
	doBench(NULL);
#endif

	elapsedTime = rdtscp() - startTime;//difftime(time(NULL), startTime);
	cpuTime = rdtscp() - startTime;//(double)(clock()-startCPU) / (double)CLK_TCK;

	fprintf_silent(stderr, "\n");
	fprintf(stderr, "\nTotal elapsed time"
#ifdef SYS_MULTI_THREAD
			  " for %d threads"
#endif
			  ": %lu (%lu CPU)\n",//": %.2f (%.4f CPU)\n",
#ifdef SYS_MULTI_THREAD
			  uThreadCount,
#endif
			  elapsedTime, cpuTime);

}

void doBench(void *arg)
{ 
  char **memory = malloc(ulCallCount * sizeof(void *));
  int	size_base, size, iterations;
  int	repeat = ulCallCount;
  char **mp = memory;
  char **mpe = memory + ulCallCount;
  char **save_start = mpe;
  char **save_end = mpe;

  while (repeat--)  
  { 
    for (size_base = 1;
		 size_base < uMaxBlockSize;
		 size_base = size_base * 3 / 2 + 1)
    { 
      for (size = size_base; size; size /= 2)
      {
			/* allocate smaller blocks more often than large */
			iterations = 1;

			if (size < 10000)
				iterations = 10;

			if (size < 1000)
				iterations *= 5;

			if (size < 100)
				iterations *= 5;

			while (iterations--)
			{ 

				if (!memory || !(*mp ++ = (char *)malloc(size)))
				{
					printf("Out of memory\n");
					//_exit (1);
				}

	  /* while allocating skip over that portion of the buffer that still
	     holds pointers from the previous cycle
           */
	  if (mp == save_start)
	    mp = save_end;

	  if (mp >= mpe)   /* if we've reached the end of the malloc buffer */
	  { mp = memory;
            
	    /* mark the next portion of the buffer */
	    save_start = save_end;  
	    if (save_start >= mpe)	save_start = mp;
	    save_end = save_start + (ulCallCount / 5);
	    if (save_end > mpe)		save_end = mpe;
            
	    /* free the bottom and top parts of the buffer.
	     * The bottom part is freed in the order of allocation.
	     * The top part is free in reverse order of allocation.
	     */
	    while (mp < save_start)
	      free (*mp ++);

		 mp = mpe;

	    while (mp > save_end)
	      free (*--mp);

	    mp = memory;
	  }
	}
      }
    }
  }
  /* free the residual allocations */
  mpe = mp;
  mp = memory;

  while (mp < mpe)
    free (*mp ++);

  free(memory);
}

unsigned long promptAndRead(char *msg, unsigned long defaultVal, char fmtCh)
{
		return defaultVal;
}


/*** System-Specific Interfaces ***/

#ifdef SYS_MULTI_THREAD
ThreadID RunThread(void (*fn)(void *), void *arg)
{
	ThreadID result = THREAD_NULL;
	
    static int cpu = 0; 
    if(cpu <= 1) cpu = nautilus_info.sys.num_cpus;
    if(nk_thread_start(fn,arg,0,0,TSTACK_DEFAULT,&result,--cpu) != 0)
		return THREAD_NULL;

	return result;
}

/* wait for all benchmark threads to terminate */
void WaitForThreads(ThreadID tids[], unsigned tidCnt)
{
	while (tidCnt--)
		pthread_join(tids[tidCnt], NULL);
}

#ifdef __hpux
#include <sys/pstat.h>
/*#include <sys/mpctl.h>*/
#elif defined(__DGUX__)
#include <sys/dg_sys_info.h>
#endif

#endif /* SYS_MULTI_THREAD */
static struct shell_cmd_impl shbench_impl = {
    .cmd      = "shbench",
    .help_str = "shbench callcount min max", 
    .handler  = handle_shbench,
};
nk_register_shell_cmd(shbench_impl);
