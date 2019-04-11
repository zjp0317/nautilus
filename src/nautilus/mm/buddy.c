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
 * http://xtack.sandia.gov/hobbes
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
 *
 * This file includes code borrowed from the Kitten LWK, with modifications
 */
#include <nautilus/nautilus.h>
#include <nautilus/mm.h>
#include <nautilus/paging.h>
#include <nautilus/buddy.h>
#include <nautilus/naut_types.h>
#include <nautilus/list.h>
#include <nautilus/naut_assert.h>
#include <nautilus/math.h>
#include <nautilus/macros.h>

#include <lib/bitmap.h>

#ifndef NAUT_CONFIG_DEBUG_BUDDY
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...)
#endif

#define BUDDY_DEBUG(fmt, args...) DEBUG_PRINT("BUDDY: " fmt, ##args)
#define BUDDY_PRINT(fmt, args...) printk("BUDDY: " fmt, ##args)
#define BUDDY_WARN(fmt, args...)  WARN_PRINT("BUDDY: " fmt, ##args)

/**
 * __set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline void 
__set_bit (ulong_t nr, volatile void * addr)
{
    
    __asm__ __volatile__ (
        "btsq %1,%0"
        :"+m" (*(volatile long*)addr)
        :"r" (nr) : "memory");
}


static inline void 
__clear_bit (ulong_t nr, volatile void * addr)
{
    __asm__ __volatile__ (
        "btrq %1,%0"
        :"+m" (*(volatile long*)addr)
        :"r" (nr));
}

static inline void setb(ulong_t nr, volatile char *addr)
{
    ulong_t offset, bitoffset;
    offset = nr/8;
    bitoffset = nr % 8;

    addr[offset] |= (0x1UL << bitoffset);

}

static inline void clearb(ulong_t nr, volatile char *addr)
{
    ulong_t offset, bitoffset;
    offset = nr/8;
    bitoffset = nr % 8;

    addr[offset] &= ~(0x1UL << bitoffset);

}
/**
 * Converts a block address to its block index in the specified buddy allocator.
 * A block's index is used to find the block's tag bit, mp->tag_bits[block_id].
 */
static inline ulong_t
block_to_id (struct buddy_mempool *mp, struct block *block)
{
    ulong_t block_id =
        ((ulong_t)block - mp->base_addr) >> mp->min_order;
#if 0
    if (block_id >= mp->num_blocks) {
        printk("The block %p\n", block);
        printk("Block ID is greater than the number of blocks in this pool!\n"
              "    MemPool Base Addr: %p\n"
              "    MemPool Size:    0x%lx\n"
              "    Min Order:       %u\n"
              "    Num Blocks:      0x%lx\n"
              "    Block ID :       0x%lx\n", 
              mp->base_addr,
              1UL<<mp->pool_order,
              mp->min_order,
              mp->num_blocks,
              block_id);

    }
#endif
    ASSERT(block_id < mp->num_blocks);

    return block_id;
}

/**
 * Marks a block as free by setting its tag bit to one.
 */
static inline void
mark_available (struct buddy_mempool *mp, ulong_t block_id)
{
    __set_bit(block_id, (volatile char*)mp->tag_bits);
}

/**
 * Marks a block as allocated by setting its tag bit to zero.
 */
static inline void
mark_allocated (struct buddy_mempool *mp, ulong_t block_id)
{
    __clear_bit(block_id, (volatile char *)mp->tag_bits);
}

/**
 * Returns true if block is free, false if it is allocated.
 */
static inline int
is_available (struct buddy_mempool *mp, struct block *block)
{
    return test_bit(block_to_id(mp, block), mp->tag_bits);
}

/* zjp:
 * Set the order bit (only the last bit) for the block 
 */
static inline void
set_order_bit(struct buddy_mempool *mp, ulong_t block_id, ulong_t order)
{
    __set_bit(block_id + (1ULL<<(order - mp->min_order)) - 1,
            (volatile char*)mp->order_bits);
}

/* zjp:
 * Clear the order bit (only the last bit) for the block 
 */
static inline void
clear_order_bit(struct buddy_mempool *mp, ulong_t block_id, ulong_t order)
{
    __clear_bit(block_id + (1ULL<<(order - mp->min_order)) - 1,
            (volatile char*)mp->order_bits);
}

/* zjp:
 * Return the order of a block
 */
inline uint64_t 
get_block_order(struct buddy_mempool *mp, void *block) {
    ulong_t block_id = block_to_id(mp, block);
    int start = block_id;
    while( ! test_bit(block_id++, mp->order_bits));
    return ilog2(block_id - start) + mp->min_order;
}

/**
 * Returns the address of the block's buddy block.
 */
static void *
find_buddy (struct buddy_mempool *mp, struct block *block, ulong_t order)
{
    ulong_t _block;
    ulong_t _buddy;

    ASSERT((ulong_t)block >= mp->base_addr);

    /* Fixup block address to be zero-relative */
    _block = (ulong_t)block - mp->base_addr;

    /* Calculate buddy in zero-relative space */
    _buddy = _block ^ (1UL << order);

    /* Return the buddy's address */
    return (void *)(_buddy + mp->base_addr);
}

struct buddy_memzone *
buddy_init (uint_t  node_id,
            ulong_t max_order,
            ulong_t min_order)
{
    struct buddy_memzone *zone = NULL;
    ulong_t i;

    BUDDY_DEBUG("Initializing Memory zone with up to %lu bit blocks on Node %d\n", max_order, node_id);

    /* Smallest block size must be big enough to hold a block structure */
    if ((1UL << min_order) < sizeof(struct block)) {
        min_order = ilog2( roundup_pow_of_two(sizeof(struct block)) );
        BUDDY_DEBUG("min order fixed to %lu\n",min_order);
    }

    /* The minimum block order must be smaller than the max order */
    if (min_order > max_order) {
        BUDDY_DEBUG("Skipping buddy init as required pool order is too small min_order=%lu pool_order=%lu\n", min_order, max_order);
        return NULL;
    }

    zone = mm_boot_alloc(sizeof(struct buddy_memzone));
    if (!zone) {
        ERROR_PRINT("Could not allocate memzone\n");
        return NULL;
    }
    memset(zone, 0, sizeof(struct buddy_memzone));

    zone->max_order = max_order;
    zone->min_order = min_order;
    zone->node_id   = node_id;

    /* Allocate a list for every order up to the maximum allowed order */
    zone->avail = mm_boot_alloc((max_order + 1) * sizeof(struct list_head));

    if (!zone->avail) { 
        ERROR_PRINT("Cannot allocate list heads\n");
        return NULL;
    }

    /* Initially all lists are empty */
    for (i = 0; i <= max_order; i++) {
        INIT_LIST_HEAD(&zone->avail[i]);
    }

    spinlock_init(&(zone->lock));
    INIT_LIST_HEAD(&zone->mempools);

    BUDDY_DEBUG("Created memory zone %p\n", zone);

    return zone;
}

/* zjp
 * This function should run with holding zone->lock
 */
void 
insert_mempool(struct buddy_memzone * zone,
        struct buddy_mempool * pool)
{
    list_add(&pool->link, &(zone->mempools));
    zone->num_pools++;
}

/* zjp:
 * This add a pool of a given size to a buddy allocated zone
 * ONLY used during buddy initialization
 */
struct buddy_mempool * 
buddy_init_pool(struct buddy_memzone * zone,
        ulong_t          base_addr,
        ulong_t          pool_order)
{
    struct buddy_mempool * mp = NULL;
    uint8_t flags = 0;
    int ret = 0;

    if (pool_order > zone->max_order) {
        ERROR_PRINT("Pool order size is larger than max allowable zone size (pool_order=%lu) (max_order=%lu)\n", pool_order, zone->max_order);
        return NULL;
    } else if (pool_order < zone->min_order) {
        ERROR_PRINT("Pool order is smaller than min allowable zone size (pool_order=%lu) (min_order=%lu)\n", pool_order, zone->min_order);
        return NULL;
    }

    mp = mm_boot_alloc(sizeof(struct buddy_mempool));

    if (!mp) {
        ERROR_PRINT("Could not allocate mempool\n");
        return NULL;
    }

    mp->base_addr       = base_addr;
    mp->pool_order      = pool_order;
    mp->min_order       = zone->min_order;
    mp->zone            = zone;
    mp->num_free_blocks = 0;

    /* Allocate a bitmap with 1 bit per minimum-sized block */
    mp->num_blocks      = (1UL << pool_order) / (1UL << zone->min_order);
    uint64_t bytes_for_bitmap = BITS_TO_LONGS(mp->num_blocks) * sizeof(ulong_t);
    mp->tag_bits   = mm_boot_alloc(bytes_for_bitmap);
    /* Allocate for order bits and flag bits */
    mp->order_bits = mm_boot_alloc(bytes_for_bitmap);
    mp->flag_bits   = mm_boot_alloc(bytes_for_bitmap);

    /* Initially mark all minimum-sized blocks as allocated */
    bitmap_zero(mp->tag_bits, mp->num_blocks);
    /* initialize order bits */ 
    bitmap_zero(mp->order_bits, mp->num_blocks);
    /* initialize flag bits */
    bitmap_zero(mp->flag_bits, mp->num_blocks);

    flags = spin_lock_irq_save(&(zone->lock));
    {
        insert_mempool(zone, mp);
    }
    spin_unlock_irq_restore(&(zone->lock), flags);

    // During init, don't do free here!!  The initial free blocks will be added back by mm_boot_kmem_init
    //buddy_free(mp, (void*)base_addr, pool_order);

    BUDDY_DEBUG("Added memory pool (addr=%p), order=%lu\n", (void *)base_addr, pool_order);

    return mp;
}

/* zjp:
 * This create a pool of a given size for a buddy allocated zone.
 * ONLY used after buddy allocator is initialized. 
 * NOTE that: 
 *   1. it does not insert the new pool to the zone's pool list
 *   2. it does not do the initial buddy_free
 */
struct buddy_mempool * 
buddy_create_pool(struct buddy_memzone * zone,
        ulong_t          base_addr,
        ulong_t          pool_order)
{
    struct buddy_mempool * mp = NULL;
    uint8_t flags = 0;
    int ret = 0;

    if (pool_order > zone->max_order) {
        ERROR_PRINT("Pool order size is larger than max allowable zone size (pool_order=%lu) (max_order=%lu)\n", pool_order, zone->max_order);
        return NULL;
    } else if (pool_order < zone->min_order) {
        ERROR_PRINT("Pool order is smaller than min allowable zone size (pool_order=%lu) (min_order=%lu)\n", pool_order, zone->min_order);
        return NULL;
    }

    mp = kmem_malloc(sizeof(struct buddy_mempool));

    if (!mp) {
        ERROR_PRINT("Could not allocate mempool\n");
        return NULL;
    }

    mp->base_addr       = base_addr;
    mp->pool_order      = pool_order;
    mp->min_order       = zone->min_order;
    mp->zone            = zone;
    mp->num_free_blocks = 0;

    /* Allocate a bitmap with 1 bit per minimum-sized block */
    mp->num_blocks      = (1UL << pool_order) / (1UL << zone->min_order);
    uint64_t bytes_for_bitmap = BITS_TO_LONGS(mp->num_blocks) * sizeof(ulong_t);
    mp->tag_bits   = kmem_malloc(bytes_for_bitmap);
    /* Allocate for order bits and flag bits */
    mp->order_bits = kmem_malloc(bytes_for_bitmap);
    mp->flag_bits   = kmem_malloc(bytes_for_bitmap);

    /* Initially mark all minimum-sized blocks as allocated */
    bitmap_zero(mp->tag_bits, mp->num_blocks);
    /* initialize order bits */ 
    bitmap_zero(mp->order_bits, mp->num_blocks);
    /* initialize flag bits */
    bitmap_zero(mp->flag_bits, mp->num_blocks);

#if 0 // We should alloc unit hash entries first before actually 'adding' the pool
    flags = spin_lock_irq_save(&(zone->lock));
    {
        insert_mempool(zone, mp);
    }
    spin_unlock_irq_restore(&(zone->lock), flags);

    buddy_free(mp, (void*)base_addr, pool_order);
#endif

    BUDDY_DEBUG("Added memory pool (addr=%p), order=%lu\n", (void *)base_addr, pool_order);

    return mp;
}

/* zjp:
 * Removes a mempool, if it's not in-use
 * TODO: 
 *   Removal of the mempool used for boot should not be allowed
 */
int
buddy_remove_pool(struct buddy_mempool * mp)
{
    uint8_t flags = 0;
    struct buddy_memzone *zone = mp->zone;

    flags = spin_lock_irq_save(&(zone->lock));

    // zjp: TODO current code only checks the 1st block !!
    struct block * block = (struct block *)(mp->base_addr);

    if (!is_available(mp, block)) {
        ERROR_PRINT("Trying to remove an in-use memory pool %p base_addr %lx\n", mp, mp->base_addr);
        spin_unlock_irq_restore(&(zone->lock), flags);
        return -1;
    }

    list_del(&(block->link));
    list_del_init(&mp->link);
    zone->num_pools--;

    spin_unlock_irq_restore(&(zone->lock), flags);

    kmem_free(mp->tag_bits);
    kmem_free(mp->order_bits);
    kmem_free(mp->flag_bits);
    kmem_free(mp);

    return 0;
}

/**
 * Allocates a block of memory of the requested size (2^order bytes).
 *
 * Arguments:
 *       [IN] zone:  Buddy system memory allocator object.
 *       [IN] order: Block size to allocate (2^order bytes).
 *
 * Returns:
 *       Success: Pointer to the start of the allocated memory block.
 *       Failure: NULL
 */
void *
buddy_alloc (struct buddy_memzone *zone, ulong_t order)
{
    ulong_t j;
    uint8_t flags = 0;
    struct list_head *list;
    struct block *block;
    struct block *buddy_block;

    ASSERT(zone);

    BUDDY_DEBUG("BUDDY ALLOC on zone: %p order: %lu\n", zone, order);
    if (order > zone->max_order) {
        BUDDY_DEBUG("order is too big\n");
        return NULL;
    }

    /* Fixup requested order to be at least the minimum supported */
    if (order < zone->min_order) {
        order = zone->min_order;
        BUDDY_DEBUG("order expanded to %lu\n", order);
    }

    flags = spin_lock_irq_save(&(zone->lock));

    for (j = order; j <= zone->max_order; j++) {

        /* Try to allocate the first block in the order j list */
        list = &zone->avail[j];

        if (list_empty(list)) {
            BUDDY_DEBUG("Skipping order %lu as the list is empty\n",j);
            continue;
        }

        block = list_first_entry(list, struct block, link);
        list_del_init(&block->link);

        struct buddy_mempool* mp = block->mempool;

        ulong_t block_id = block_to_id(mp, block);
        set_order_bit(mp, block_id, order); // set order bit 
        mark_allocated(mp, block_id);

        BUDDY_DEBUG("Found block %p at order %lu\n",block,j);

        /* Trim if a higher order block than necessary was allocated */
        while (j > order) {
            --j;
            buddy_block = (struct block *)((ulong_t)block + (1UL << j));
            buddy_block->order = j;

            buddy_block->mempool = mp;
            block_id = block_to_id(mp, buddy_block);
            mark_available(mp, block_id);

            BUDDY_DEBUG("Inserted buddy block %p into order %lu\n",buddy_block,j);
            list_add(&buddy_block->link, &zone->avail[j]);
        }

        block->order = j;
        block->mempool = NULL; 

        mp->num_free_blocks -= (1UL << (order - zone->min_order));

        BUDDY_DEBUG("Returning block %p which is in memory pool %p-%p\n",block,mp->base_addr,mp->base_addr+(1ULL << mp->pool_order));
        spin_unlock_irq_restore(&(zone->lock), flags);
        return block;
    }

    spin_unlock_irq_restore(&(zone->lock), flags);
    BUDDY_DEBUG("FAILED TO ALLOCATE from zone %p - RETURNING  NULL\n", zone);

    return NULL;
}

/**
 * Returns a block of memory to the buddy system memory allocator.
 */
void
buddy_free(
    //!  Use mempool directly instead of memzone  
    struct buddy_mempool *  mp,
    //!  Address of memory block to free.
    void *        addr,
    //! Size of the memory block (2^order bytes).
    ulong_t order
)
{
    uint8_t flags = 0;

    ASSERT(mp);
    ASSERT(order <= mp->pool_order);
    ASSERT(!((uint64_t)addr % (1ULL<<order)));  // aligned to own size only

    BUDDY_DEBUG("BUDDY FREE on memory pool: %p addr=%p base=%p order=%lu\n",mp,addr,mp->base_addr, order);

    /* Fixup requested order to be at least the minimum supported */
    if (order < mp->min_order) {
        order = mp->min_order;
        BUDDY_DEBUG("updated order to %lu\n",order);
    }

    ASSERT((uint64_t)addr>=(uint64_t)(mp->base_addr) &&
	   (uint64_t)addr<(uint64_t)(mp->base_addr+(1ULL<<mp->pool_order)));

    ASSERT(order<=mp->pool_order);

    /* Overlay block structure on the memory block being freed */
    struct block * block = (struct block *) addr;
    ulong_t block_id = block_to_id(mp, block);

    ASSERT(!is_available(mp, block));

    struct buddy_memzone* zone = mp->zone;
    mp->num_free_blocks += (1UL << (order - zone->min_order));

    flags = spin_lock_irq_save(&(zone->lock));

    clear_order_bit(mp, block_id, order); // clear order bit, before merging buddy! 

    /* Coalesce as much as possible with adjacent free buddy blocks */
    while (order < mp->pool_order) {

        /* Determine our buddy block's address */
        struct block * buddy = find_buddy(mp, block, order);

        BUDDY_DEBUG("buddy at order %lu is %p\n",order,buddy);

        /* Make sure buddy is available and has the same size as us */
        if (!is_available(mp, buddy)) {
            BUDDY_DEBUG("buddy not available\n");
            break;
        }

        if (buddy->order != order) {
            BUDDY_DEBUG("buddy available but has order %lu\n",buddy->order);
            break;
        }

        BUDDY_DEBUG("buddy merge\n");

        /* OK, we're good to go... buddy merge! */
        list_del_init(&buddy->link);
        if (buddy < block) {
            block = buddy;
        }
        ++order;
        block->order = order;
    }

    /* Add the (possibly coalesced) block to the appropriate free list */
    block->order = order;
    block->mempool = mp;

    BUDDY_DEBUG("End of search: block=%p order=%lu pool_order=%lu block->order=%lu\n",block,order,mp->pool_order,block->order);

    mark_available(mp, block_id);

    BUDDY_DEBUG("End of mark: block=%p order=%lu pool_order=%lu block->order=%lu\n",block,order,mp->pool_order,block->order);

    list_add(&block->link, &zone->avail[order]);

    spin_unlock_irq_restore(&(zone->lock), flags);

    BUDDY_DEBUG("block at %p of order %lu being made available\n",block,block->order);

    if (block->order == -1) { 
        ERROR_PRINT("FAIL: block order went nuts\n");
        ERROR_PRINT("mp->base_addr=%p mp->num_blocks=%lu  mp->min_order=%lu, block=%p\n",mp->base_addr,mp->num_blocks, mp->min_order,block);
        panic("Block order\n");
    }
}

/*
  Sanity-checks and gets statistics of the buddy pool
 */
static int _buddy_sanity_check(struct buddy_mempool *mp, struct buddy_pool_stats *stats)
{
    // zjp: TODO do this after the new structure is done
    return 0;
#if 0
    int rc;
    ulong_t i;
    ulong_t num_blocks;
    uint64_t total_bytes;
    uint64_t total_blocks;
    uint64_t min_alloc, max_alloc;
    uint8_t flags;
    struct list_head *entry;

    rc=0;

    flags = spin_lock_irq_save(&mp->lock);

    stats->start_addr = (void*)(mp->base_addr);
    stats->end_addr = (void*)(mp->base_addr + (1ULL<<mp->pool_order));

    total_bytes = 0;
    total_blocks = 0;
    min_alloc = 0;
    max_alloc = 0;

    //nk_vc_printf("buddy pool %p-%p, order=%lu, min order=%lu\n", mp->base_addr, mp->base_addr + (1ULL<<mp->pool_order),mp->pool_order,mp->min_order);

    for (i = mp->min_order; i <= mp->pool_order; i++) {

        /* Count the number of memory blocks in the list */
        num_blocks = 0;
        list_for_each(entry, &mp->avail[i])  {
	    struct block *block = list_entry(entry, struct block, link);
	    //nk_vc_printf("order %lu block %lu\n",i, num_blocks);
	    //nk_vc_printf("entry %p - block %p order %lx\n",entry, block,block->order);
	    if ((uint64_t)block<(uint64_t)mp->base_addr || 
		(uint64_t)block>=(uint64_t)(mp->base_addr+(1ULL<<mp->pool_order))) { 
		ERROR_PRINT("BLOCK %p IS OUTSIDE OF POOL RANGE (%p-%p)\n", block,
			    mp->base_addr,(mp->base_addr+(1ULL<<mp->pool_order)));
		rc|=-1;
		break;
	    }
	    if (block->order != i) { 
		ERROR_PRINT("BLOCK %p IS OF INCORRECT ORDER (%lu)\n", block, block->order);
		ERROR_PRINT("FIRST WORDS: 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n", ((uint64_t*)block)[0],((uint64_t*)block)[1],((uint64_t*)block)[2],((uint64_t*)block)[3]);
		rc|=-1;
		break;
	    }
	    if (!is_available(mp,block)) { 
		ERROR_PRINT("BLOCK %p IS NOT MARKED AVAILABLE BUT IS ON FREE LIST\n", block);
		ERROR_PRINT("FIRST WORDS: 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n", ((uint64_t*)block)[0],((uint64_t*)block)[1],((uint64_t*)block)[2],((uint64_t*)block)[3]);
		rc|=-1;
		break;
	    }
            ++num_blocks;
	}

	//nk_vc_printf("%lu blocks at order %lu\n",num_blocks,i);

	if (min_alloc==0) { 
	    min_alloc = 1ULL << mp->min_order ;
	}
	if (num_blocks>0) { 
	    max_alloc = 1ULL << i;
	}

	total_blocks += num_blocks;
	total_bytes += num_blocks * (1ULL << i);
    }
    
    stats->total_blocks_free = total_blocks;
    stats->total_bytes_free = total_bytes;
    stats->min_alloc_size = min_alloc;
    stats->max_alloc_size = max_alloc;
    
    spin_unlock_irq_restore(&mp->lock,flags);

    return rc;
#endif
}

void buddy_stats(struct buddy_mempool *mp, struct buddy_pool_stats *stats)
{
    _buddy_sanity_check(mp,stats);
}

int buddy_sanity_check(struct buddy_mempool *mp)
{
    struct buddy_pool_stats s;
    return _buddy_sanity_check(mp,&s);
}

/**
 * Dumps the state of a buddy system memory allocator object to the console.
 */
int zone_mem_show(struct  buddy_memzone * zone)
{
    unsigned long          num_blocks = 0;
    struct list_head     * entry      = NULL;
    unsigned long flags = 0;
    unsigned long i     = 0;

    if (!zone) {
        BUDDY_PRINT("Null Zone Pointer!!\n");
        return 0;
    }
    BUDDY_PRINT("DUMP OF BUDDY MEMORY ZONE:\n");
    BUDDY_PRINT("  Zone Max Order=%lu, Min Order=%lu\n",
            zone->max_order, zone->min_order);

    flags = spin_lock_irq_save(&(zone->lock));

    for (i = zone->min_order; i <= zone->max_order; i++) {
        /* Count the number of memory blocks in the list */
        num_blocks = 0;
        list_for_each(entry, &zone->avail[i]) {
            ++num_blocks;
        }
        BUDDY_PRINT("  order %2lu: %lu free blocks\n", i, num_blocks);
    }
    BUDDY_PRINT(" %lu memory pools\n", zone->num_pools);
    // list pools in zone
    struct buddy_mempool* pool = NULL;
    list_for_each_entry(pool, &(zone->mempools), link) {
        BUDDY_PRINT("    Base Addr=%p, order=%lu, size=%lu, free=%lu\n",
                (void *)pool->base_addr, pool->pool_order, (1UL << pool->pool_order),
                pool->num_free_blocks << zone->min_order);
    }
    spin_unlock_irq_restore(&(zone->lock), flags);
    return 0;
}
