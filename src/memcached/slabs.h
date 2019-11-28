/* slabs memory allocation */
#ifndef SLABS_H
#define SLABS_H

/** Init the subsystem. 1st argument is the limit on no. of bytes to allocate,
    0 if no limit. 2nd argument is the growth factor; each slab will use a chunk
    size equal to the previous slab's chunk size times this factor.
    3rd argument specifies if the slab allocator should allocate all memory
    up front (if true), or allocate memory in chunks as it is needed (if false)
*/
void slabs_init(const size_t limit, const double factor, const bool prealloc, const uint32_t *slab_sizes, void *mem_base_external, bool reuse_mem);

/** Call only during init. Pre-allocates all available memory */
void slabs_prefill_global(void);

/**
 * Given object size, return id to use when allocating/freeing memory for object
 * 0 means error: can't store such a large object
 */

unsigned int slabs_clsid(const size_t size);
unsigned int slabs_size(const int clsid);

/** Allocate object of given length. 0 on error */ /*@null@*/
#define SLABS_ALLOC_NO_NEWPAGE 1
void *slabs_alloc(const size_t size, unsigned int id, unsigned int flags);

/** Free previously allocated object */
void slabs_free(void *ptr, size_t size, unsigned int id);

/** Adjust global memory limit up or down */
bool slabs_adjust_mem_limit(size_t new_mem_limit);

unsigned int global_page_pool_size(bool *mem_flag);

/* Hints as to freespace in slab class */
unsigned int slabs_available_chunks(unsigned int id, bool *mem_flag, unsigned int *chunks_perslab);

void slabs_mlock(void);
void slabs_munlock(void);

enum reassign_result_type {
    REASSIGN_OK=0, REASSIGN_RUNNING, REASSIGN_BADCLASS, REASSIGN_NOSPARE,
    REASSIGN_SRC_DST_SAME
};

unsigned int slabs_fixup(char *chunk, const int border);

#endif
