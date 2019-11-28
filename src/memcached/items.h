#if 0
#define HOT_LRU 0
#define WARM_LRU 64
#define COLD_LRU 128
#define TEMP_LRU 192

#define CLEAR_LRU(id) (id & ~(3<<6))
#define GET_LRU(id) (id & (3<<6))
#endif
/* See items.c */
uint64_t get_cas_id(void);
void set_cas_id(uint64_t new_cas);

/*@null@*/
item *do_item_alloc(char *key, const size_t nkey, const unsigned int flags, const rel_time_t exptime, const int nbytes);
item_chunk *do_item_alloc_chunk(item_chunk *ch, const size_t bytes_remain);
item *do_item_alloc_pull(const size_t ntotal, const unsigned int id);
void item_free(item *it);
bool item_size_ok(const size_t nkey, const int flags, const int nbytes);

int  do_item_link(item *it, const uint32_t hv);     /** may fail if transgresses limits */
void do_item_unlink(item *it, const uint32_t hv);
void do_item_remove(item *it);
int  do_item_replace(item *it, item *new_it, const uint32_t hv);

item *do_item_get(const char *key, const size_t nkey, const uint32_t hv, conn *c, const bool do_update);
item *do_item_touch(const char *key, const size_t nkey, uint32_t exptime, const uint32_t hv, conn *c);
void do_item_bump(conn *c, item *it, const uint32_t hv);

extern pthread_mutex_t lru_locks[POWER_LARGEST];

#define STORAGE_delete(...)
