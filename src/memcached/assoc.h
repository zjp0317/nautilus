/* associative array */
int assoc_init(const int hashpower_init);
item *assoc_find(const char *key, const size_t nkey, const uint32_t hv);
int assoc_insert(item *item, const uint32_t hv);
void assoc_delete(const char *key, const size_t nkey, const uint32_t hv);
void do_assoc_move_next_bucket(void);
void assoc_start_expand(uint64_t curr_items);
extern unsigned int hashpower;
extern unsigned int item_lock_hashpower;
