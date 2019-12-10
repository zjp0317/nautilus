/* 
 * This file is part of the Nautilus AeroKernel developed
 * by the Hobbes and V3VEE Projects with funding from the 
 * United States National  Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  The Hobbes Project is a collaboration
 * led by Sandia National Laboratories that includes several national 
 * laboratories and universities. You can find out more at:
 * http://www.v3vee.org  and
 * http://xstack.sandia.gov/hobbes
 *
 * Copyright (c) 2015, Kyle C. Hale <kh@u.northwestern.edu>
 * Copyright (c) 2015, The V3VEE Project  <http://www.v3vee.org> 
 *                     The Hobbes Project <http://xstack.sandia.gov/hobbes>
 * All rights reserved.
 *
 * Author: Kyle C. Hale <kh@u.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "LICENSE.txt".
 */
#ifndef __BUDDY_H__
#define __BUDDY_H__

#include <nautilus/naut_types.h>
#include <nautilus/spinlock.h>

#define NAUT_CONFIG_PISCES_DYNAMIC 1 // TODO move this to menuconfig

#ifdef NAUT_CONFIG_PISCES_DYNAMIC
/* CAPACITY_FACTOR:
 *  Each order must have its capacity
 *   >= (CAPACITY_FACTOR * allocated).
 *  The larget this factor is, the more aggressive
 *  the prefetching is.
 */
#define CAPACITY_FACTOR  ((double)(1))

#define HARD_PREFETCH_TRIES 10 // when malloc return NULL, try 10 times to fetch memory

struct block_freelist {
    struct list_head    link;
    size_t              allocated;
    size_t              capacity;
};

void buddy_prefetch_init (void (*func)());

struct buddy_memzone;

int hard_prefetch(struct buddy_memzone*);
#endif


struct buddy_memzone {
    ulong_t     max_order;      /* max size of memory pool = 2^max_order */
    ulong_t     min_order;      /* minimum allocatable block size */

    uint_t      node_id;        /* The NUMA node this zone allocates */

    uint_t      is_mirror;       /* this zone is a mirror on other zone */

    ulong_t     num_pools;

#ifdef NAUT_CONFIG_PISCES_DYNAMIC
    struct block_freelist * avail;
    ulong_t  mem_dynamic_inprogress;
#else
    struct list_head * avail;   /* one free list for each block size,
                                 * indexed by block order:
                                 *   avail[i] = free list of 2^i 
                                 */
#endif

    spinlock_t  lock;           /* For now we will lock all zone operations...
                                 *   Hopefully this does not cause a performance 
                                 */

    struct list_head mempools;  /* since we have hash for pools, we don't need rbtree */
};


/*
 * Large object map: support quick retrieval of the order info of large objects.
 *
 * -- Treat objects larger than (1 << LARGE_OBJ_ORDER) Bytes as large objects 
 * -- For buddy pools that initially is fully free:
 *      All large objects can only start at a certain offset.
 *      E.g., assume LARGE_OBJ_ORDER = 17, an 128MB pool with starting address 0x0 
 *      can only provide large objects at offset 0B, 128KB, 256KB, 384KB,...,etc.
 *
 *      So, the offset can be used as index to retrieve order value from map (an array). 
 *
 * -- For buddy pools that 'overlap with' boot allocator:
 *      A large object may start at a 'weird' offset due to boot alloc/free,
 *      in this case, this map is a partial map that only covers some objects.
 *      The worst (though unlikely) case is that this map doesn't catch any large objects
 *      at all. But it won't hurt performance, though waste a small portion of memory.
 */

#define LARGE_OBJ_MAP   1

#ifdef LARGE_OBJ_MAP 
#define LARGE_OBJ_ORDER 17 // consider 128KB as large object
#define LARGE_OBJ_MASK  ((1UL<<LARGE_OBJ_ORDER) - 1) 
#endif

struct buddy_mempool {
    ulong_t    base_addr;       /* base address of the memory pool */
    ulong_t    pool_order;      /* size of memory pool = 2^pool_order */
    ulong_t    min_order;       /* minimum allocatable block size */

    ulong_t    num_blocks;      /* number of bits in tag_bits */
    ulong_t    num_free_blocks;

    ulong_t    *tag_bits;       /* one bit for each 2^min_order block:
                                 *   0 = block is allocated
                                 *   1 = block is available 
                                 */
    ulong_t    *order_bits;     /* one bit for each 2^min_order block:
                                 *   only the last block is set 
                                 * Traverse the order bits till an '1' to get the order value. 
                                 */
                                    
    ulong_t    *flag_bits;      /* Since nautilus currently only has one flag: VISITED,
                                 * one bit for each 2^min_order block: 
                                 *    1 = block is VISITED
                                 */

#ifdef LARGE_OBJ_MAP 
    uint8_t     *large_obj_map; /* each entry stores the order value of a large object
                                 * 0 means not a large object
                                 */
#endif

    struct buddy_memzone * zone;
    
    struct list_head link;
};

/**
 * Each free block has one of these structures at its head. The link member
 * provides linkage for the mp->avail[order] free list, where order is the
 * size of the free block.
 */
struct block {
    struct list_head link;
    ulong_t    order;
    struct buddy_mempool * mempool;
};

struct buddy_memzone * buddy_init (uint_t node_id, ulong_t max_order, ulong_t min_order);
struct buddy_memzone * buddy_create (uint_t node_id, ulong_t max_order, ulong_t min_order);

struct buddy_mempool * buddy_init_pool (struct buddy_memzone * zone, ulong_t base_addr, ulong_t pool_order);

void insert_mempool (struct buddy_memzone * zone, struct buddy_mempool * pool);
void buddy_cleanup_pool(struct buddy_mempool *mp);
struct buddy_mempool * buddy_create_pool (struct buddy_memzone * zone, ulong_t base_addr, ulong_t pool_order);
int buddy_remove_pool (struct buddy_mempool * mp);

int zone_mem_show(struct  buddy_memzone * zone);

inline ulong_t get_block_order (struct buddy_mempool *mp, void *block);

#ifdef NAUT_CONFIG_PISCES_DYNAMIC
void buddy_free (char is_new_mem, struct buddy_mempool * mp, void * addr, ulong_t order);
#else
void buddy_free (struct buddy_mempool * mp, void * addr, ulong_t order);
#endif
void * buddy_alloc (struct buddy_memzone * zone, ulong_t order);

int  buddy_sanity_check(struct buddy_mempool *mp);

struct buddy_pool_stats {
    void   *start_addr;
    void   *end_addr;
    uint64_t total_blocks_free;
    uint64_t total_bytes_free;
    uint64_t min_alloc_size;
    uint64_t max_alloc_size;
};

void buddy_stats(struct buddy_mempool *mp, struct buddy_pool_stats *stats);


#endif
