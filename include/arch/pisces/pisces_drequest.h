#ifndef __PISCES_DREQUEST_H__
#define __PISCES_DREQUEST_H__

#include <arch/pisces/pisces_boot_params.h>

#define DREQUEST_ADDR_SHIFT 12
#define DREQUEST_MSG_SIZE   8

inline u64 atomic_get64(u64 * ptr);
inline void atomic_set64(u64 * ptr, u64 val);
    
inline void drequest_wait_for_prefetch();
inline void drequest_wakeup_for_prefetch();

inline void drequest_set_removal_msg(u64 msg, u64 idx);
inline void drequest_set_removal_msg_len(u32 len);

inline int claim_removal_dchan();
inline int release_removal_dchan();

inline void drequest_try_prefetch();
inline void drequest_confirm_remove();

int drequest_init();
#endif
