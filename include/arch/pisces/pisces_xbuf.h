/* 
 * Copyright (c) 2013, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
 
#ifndef __PISCES_DATA_H__
#define __PISCES_DATA_H__

#include <arch/pisces/pisces_types.h>
#include <nautilus/spinlock.h>

//#include <nautilus/queue.h>
#include <nautilus/waitqueue.h>

struct pisces_xbuf;
struct pisces_enclave;

struct pisces_xbuf_desc {
    struct pisces_xbuf * xbuf;

    spinlock_t xbuf_lock;
    //nk_queue_t    xbuf_waitq;
    nk_wait_queue_t xbuf_waitq;
    void     * private_data;

    void (*recv_handler)(u8 * data, u32 data_len, void * priv_data);

};


struct pisces_xbuf_desc * 
pisces_xbuf_server_init(uintptr_t   xbuf_va, 
			u32         xbuf_total_bytes,  
			void      (*recv_handler)(u8 * data, u32 data_len, void * priv_data),
			void      * priv_data,
			u32         ipi_vector,
			u32         target_cpu);

int
pisces_xbuf_server_deinit(struct pisces_xbuf_desc * xbuf_desc);


struct pisces_xbuf_desc *  
pisces_xbuf_client_init(uintptr_t xbuf_va, 
			u32       ipi_vector, 
			u32       target_cpu);



int 
pisces_xbuf_sync_send(struct pisces_xbuf_desc * desc,
		      u8                      * data, 
		      u32                       data_len, 
		      u8                     ** resp_data, 
		      u32                     * resp_len);


int
pisces_xbuf_send(struct pisces_xbuf_desc * desc, 
		 u8                      * data, 
		 u32                       data_len);


int 
pisces_xbuf_complete(struct pisces_xbuf_desc * desc, 
		     u8                      * data, 
		     u32                       data_len);


int pisces_xbuf_pending(struct pisces_xbuf_desc * desc);
int pisces_xbuf_recv(struct pisces_xbuf_desc * desc, u8 ** data, u32 * data_len);

int pisces_xbuf_enable(struct pisces_xbuf_desc * xbuf_desc);
int pisces_xbuf_disable(struct pisces_xbuf_desc * xbuf_desc);

#endif
