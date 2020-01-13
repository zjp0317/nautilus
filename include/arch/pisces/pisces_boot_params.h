/*
 * Pisces Booting Protocol
 * This file is shared with enclave OS
 */
#ifndef _PISCES_BOOT_PARAMS_H_
#define _PISCES_BOOT_PARAMS_H_

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

#define PISCES_MAGIC 0x000FE110

/* Pisces Boot loader memory layout

 * 1. boot parameters // 4KB aligned
 *     ->  Trampoline code sits at the start of this structure 
 * 2. Console ring buffer (64KB) // 4KB aligned
 * 3. To enclave CMD buffer  // (4KB)
 * 4. From enclave CMD buffer // (4KB)
 * 4. kernel image // bootmem + 2MB (MUST be loaded at the 2MB offset)
 * 5. initrd // 2M aligned
 *
 */


/* All addresses in this structure are physical addresses */
struct pisces_boot_params {

    // Embedded asm to load esi and jump to kernel
    union {
	u64 launch_code[8];
	struct {
	    u8    launch_code_asm[48];
	    u64   launch_code_esi;
	    u64   launch_code_target_addr;
	} __attribute__((packed));
    } __attribute__((packed));

    u8 init_dbg_buf[16];
    

    u64 magic;
    
    union {
	u64 flags;
	struct {
	    u64 initialized  : 1;
	    u64 flags__rsvd  : 63;
	} __attribute__((packed));
    } __attribute__((packed));
    

    u64 boot_params_size;

    u64 cpu_id;
    u64 apic_id;
    u64 cpu_khz;

    u64 trampoline_code_pa;

    // coordinator domain cpu apic id
    u64 domain_xcall_master_apicid;

    // domain cross call vector id
    u64 domain_xcall_vector;

    // cmd_line
    char cmd_line[1024];

    // kernel
    u64 kernel_addr;
    u64 kernel_size;

    // initrd
    u64 initrd_addr;
    u64 initrd_size;


    // The address of the ring buffer used for the early console
    u64 console_ring_addr;
    u64 console_ring_size;

    // Address and size of the linux->enclave command/control channel
    u64 control_buf_addr;
    u64 control_buf_size;

    // Address and size of the enclave->linux command/control channel
    u64 longcall_buf_addr;
    u64 longcall_buf_size;

    // Address and size of the enclave->linux XPMEM channel
    u64 xpmem_buf_addr;
    u64 xpmem_buf_size;

    u64 base_mem_paddr;
    u64 base_mem_size;
    
    // Memory info: num_blocks * block_size = base_mem_size 
    u64 num_blocks;
    u64 block_size;

    // drequest
    u64 drequest_mem_info; // l1, l2
    u64 prefeching_dchan_addr;
    u64 removal_dchan_addr;
} __attribute__((packed));

extern struct pisces_boot_params *pisces_boot_params;
#endif
