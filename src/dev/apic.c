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
 */
#include <nautilus/cpu.h>
#include <nautilus/cpuid.h>
#include <nautilus/msr.h>
#include <nautilus/irq.h>
#include <nautilus/paging.h>
#include <nautilus/nautilus.h>
#include <nautilus/percpu.h>
#include <nautilus/intrinsics.h>
#include <nautilus/mm.h>
#include <dev/apic.h>
#include <dev/i8254.h>
#include <dev/timer.h>
#include <lib/bitops.h>

#ifndef NAUT_CONFIG_DEBUG_APIC
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...)
#endif

#define APIC_DEBUG(fmt, args...) DEBUG_PRINT("APIC: " fmt, ##args)
#define APIC_PRINT(fmt, args...) INFO_PRINT("APIC: " fmt, ##args)
#define APIC_WARN(fmt, args...)  WARN_PRINT("APIC: " fmt, ##args)
#define APIC_ERROR(fmt, args...) ERROR_PRINT("APIC: " fmt, ##args)

static const char * apic_err_codes[8] = {
    "[Send Checksum Error]",
    "[Receive Checksum Error]",
    "[Send Accept Error]",
    "[Receive Accept Error]",
    "[Redirectable IPI]",
    "[Send Illegal Vector]",
    "[Receive Illegal Vector]",
    "[Illegal Register Address]"
};


static int
spur_int_handler (excp_entry_t * excp, excp_vec_t v)
{
    APIC_WARN("APIC (ID=0x%x) Received Spurious Interrupt on core %u\n",
        per_cpu_get(apic)->id,
        my_cpu_id());

    struct apic_dev * a = per_cpu_get(apic);
    a->spur_int_cnt++;

    /* we don't need to EOI here */
    return 0;
}

static int
null_kick (excp_entry_t * excp, excp_vec_t v)
{
    IRQ_HANDLER_END();
    return 0;
}

static int
error_int_handler (excp_entry_t * excp, excp_vec_t v)
{
    struct apic_dev * apic = per_cpu_get(apic);
    char * s = "[Unknown Error]";
    uint8_t i = 0;
    uint32_t err = 0;

    apic_write(apic, APIC_REG_ESR, 0);
    err = apic_read(apic, APIC_REG_ESR);
    apic_do_eoi();

    apic->err_int_cnt++;

    err &= 0xff;

    APIC_WARN("Error interrupt recieved from local APIC (ID=0x%x) on Core %u (error=0x%x):\n", 
            per_cpu_get(apic)->id, my_cpu_id(), err);

    while (err) {

        if (err & 0x1) {
            s = (char*)apic_err_codes[i];
            APIC_WARN("\t%s\n", s);
        }

        ++i;
        err >>= 1;
    }

    return 0;
}


static int
dummy_int_handler (excp_entry_t * excp, excp_vec_t v)
{
    panic("Received an interrupt from an Extended LVT vector  on LAPIC (0x%x) on core %u (Should be masked)\n",
        per_cpu_get(apic)->id,
        my_cpu_id());

    return 0;
}


static int
pc_int_handler (excp_entry_t * excp, excp_vec_t v)
{
    panic("Received a performance counter interrupt from the LAPIC (0x%x) on core %u (Should be masked)\n",
        per_cpu_get(apic)->id,
        my_cpu_id());

    return 0;
}


static int
thermal_int_handler (excp_entry_t * excp, excp_vec_t v)
{
    panic("Received a thermal interrupt from the LAPIC (0x%x) on core %u (Should be masked)\n",
        per_cpu_get(apic)->id,
        my_cpu_id());

    return 0;
}


static uint8_t
check_apic_avail (void)
{
    cpuid_ret_t cp;
    struct cpuid_feature_flags * flags;

    cpuid(CPUID_FEATURE_INFO, &cp);
    flags = (struct cpuid_feature_flags *)&cp.c;

    return flags->edx.apic;
}


static uint8_t
apic_is_bsp (struct apic_dev * apic)
{
    uint64_t data;
    data = msr_read(APIC_BASE_MSR);
    return APIC_IS_BSP(data);
}


static void
apic_sw_enable (struct apic_dev * apic)
{
    uint32_t val;
    uint8_t flags = irq_disable_save();
    val = apic_read(apic, APIC_REG_SPIV);
    apic_write(apic, APIC_REG_SPIV, val | APIC_SPIV_SW_ENABLE);
    irq_enable_restore(flags);
}


static void
apic_sw_disable (struct apic_dev * apic)
{
    uint32_t val;
    uint8_t flags = irq_disable_save();
    val = apic_read(apic, APIC_REG_SPIV);
    apic_write(apic, APIC_REG_SPIV, val & ~APIC_SPIV_SW_ENABLE);
    irq_enable_restore(flags);
}


static void
apic_assign_spiv (struct apic_dev * apic, uint8_t spiv_vec)
{
    apic_write(apic, 
            APIC_REG_SPIV,
            apic_read(apic, APIC_REG_SPIV) | spiv_vec);
}


static inline void
apic_global_enable (void)
{
    msr_write(APIC_BASE_MSR, msr_read(APIC_BASE_MSR) | APIC_GLOBAL_ENABLE);
}

static ulong_t 
apic_get_base_addr (void) 
{
    uint64_t data;
    data = msr_read(APIC_BASE_MSR);

    // we're assuming PAE is on
    return (addr_t)(data & APIC_BASE_ADDR_MASK);
}


static void
apic_set_base_addr (struct apic_dev * apic, addr_t addr)
{
    uint64_t data;
    data = msr_read(APIC_BASE_MSR);
    msr_write(APIC_BASE_MSR, (addr & APIC_BASE_ADDR_MASK) | (data & 0xfff));
}


void 
apic_do_eoi (void)
{
    struct apic_dev * apic = (struct apic_dev*)per_cpu_get(apic);
    ASSERT(apic);
    apic_write(apic, APIC_REG_EOR, 0);
}


uint32_t
apic_get_id (struct apic_dev * apic)
{
    return (apic_read(apic, APIC_REG_ID) >> APIC_ID_SHIFT) & 0xff;
}


static inline uint8_t 
apic_get_version (struct apic_dev * apic)
{
    return APIC_VERSION(apic_read(apic, APIC_REG_LVR));
}


uint32_t 
apic_wait_for_send(struct apic_dev * apic)
{
    uint32_t res;
    int n = 0;

    do {
        if (!(res = apic_read(apic, APIC_REG_ICR) & ICR_SEND_PENDING)) {
            break;
        }
        udelay(100);
    } while (n++ < 1000);

    return res;
}


int 
apic_get_maxlvt (struct apic_dev * apic)
{
    uint_t v;

    v = apic_read(apic, APIC_REG_LVR);
    return ((v >> 16) & 0xffu);
}


int
apic_read_timer (struct apic_dev * apic)
{
    return apic_read(apic, APIC_REG_TMCCT);
}


void
apic_self_ipi (struct apic_dev * apic, uint_t vector)
{
    uint8_t flags = irq_disable_save();
    apic_write(apic, APIC_IPI_SELF, vector);
    irq_enable_restore(flags);
}


void 
apic_send_iipi (struct apic_dev * apic, uint32_t remote_id) 
{
    uint8_t flags = irq_disable_save();
    apic_write(apic, APIC_REG_ICR2, remote_id << APIC_ICR2_DST_SHIFT);
    apic_write(apic, APIC_REG_ICR, ICR_TRIG_MODE_LEVEL| ICR_LEVEL_ASSERT | ICR_DEL_MODE_INIT);
    irq_enable_restore(flags);
}


void
apic_deinit_iipi (struct apic_dev * apic, uint32_t remote_id)
{
    uint8_t flags = irq_disable_save();
    apic_write(apic, APIC_REG_ICR2, remote_id << APIC_ICR2_DST_SHIFT);
    apic_write(apic, APIC_REG_ICR, ICR_TRIG_MODE_LEVEL| ICR_DEL_MODE_INIT);
    irq_enable_restore(flags);
}


void
apic_send_sipi (struct apic_dev * apic, uint32_t remote_id, uint8_t target)
{
    uint8_t flags = irq_disable_save();
    apic_write(apic, APIC_REG_ICR2, remote_id << APIC_ICR2_DST_SHIFT);
    apic_write(apic, APIC_REG_ICR, ICR_DEL_MODE_STARTUP | target);
    irq_enable_restore(flags);
}


void
apic_bcast_iipi (struct apic_dev * apic) 
{
    uint8_t flags = irq_disable_save();
    apic_write(apic, APIC_REG_ICR, APIC_IPI_OTHERS | ICR_LEVEL_ASSERT | ICR_TRIG_MODE_LEVEL | ICR_DEL_MODE_INIT);
    irq_enable_restore(flags);
}


void
apic_bcast_deinit_iipi (struct apic_dev * apic)
{
    uint8_t flags = irq_disable_save();
    apic_write(apic, APIC_REG_ICR, APIC_IPI_OTHERS | ICR_TRIG_MODE_LEVEL | ICR_DEL_MODE_INIT);
    irq_enable_restore(flags);
}


void
apic_bcast_sipi (struct apic_dev * apic, uint8_t target)
{
    uint8_t flags = irq_disable_save();
    apic_write(apic, APIC_REG_ICR, APIC_IPI_OTHERS | ICR_DEL_MODE_STARTUP | target);
    irq_enable_restore(flags);
}

static void calibrate_apic_timer(struct apic_dev *apic);
static int apic_timer_handler(excp_entry_t * excp, excp_vec_t vec);


void
apic_timer_setup (struct apic_dev * apic, uint32_t quantum)
{
    uint32_t busfreq;
    uint32_t tmp;
    uint8_t  tmp2;
    cpuid_ret_t ret;
    int x2apic, tscdeadline, arat; 

    APIC_DEBUG("Setting up Local APIC timer for APIC 0x%x\n", apic->id);

    cpuid(0x1, &ret);
  
    x2apic = (ret.c >> 21) & 0x1;
    tscdeadline = (ret.c >> 24) & 0x1;

    cpuid(0x6, &ret);
    arat = (ret.a >> 2) & 0x1;

    APIC_DEBUG("APIC timer has:  x2apic=%d tscdeadline=%d arat=%d\n",
	       x2apic, tscdeadline, arat);

    if (register_int_handler(APIC_TIMER_INT_VEC,
            apic_timer_handler,
            NULL) != 0) {
        panic("Could not register APIC timer handler\n");
    }

    calibrate_apic_timer(apic);

    apic_set_oneshot_timer(apic,apic_realtime_to_ticks(apic,1000000000/NAUT_CONFIG_HZ));
}


/**
 * Converts an entry in a local APIC's Local Vector Table to a
 * human-readable string.
 * (NOTE: taken from Kitten)
 */
static char *
lvt_stringify (uint32_t entry, char *buf)
{
	uint32_t delivery_mode = entry & 0x700;

	if (delivery_mode == APIC_DEL_MODE_FIXED) {
		sprintf(buf, "FIXED -> IDT VECTOR %u",
			entry & APIC_LVT_VEC_MASK
		);
	} else if (delivery_mode == APIC_DEL_MODE_NMI) {
		sprintf(buf, "NMI   -> IDT VECTOR 2"); 
	} else if (delivery_mode == APIC_DEL_MODE_EXTINT) {
		sprintf(buf, "ExtINT, hooked to old 8259A PIC");
	} else {
		sprintf(buf, "UNKNOWN");
	}

	if (entry & APIC_LVT_DISABLED)
		strcat(buf, ", MASKED");

	return buf;
}


static inline uint8_t 
amd_has_ext_lvt (struct apic_dev * apic)
{
    uint32_t ver = apic_read(apic, APIC_REG_LVR);

    if (APIC_HAS_EXT_LVT(ver)) {
        return 1;
    }

    return 0;
}


static void
amd_setup_ext_lvt (struct apic_dev * apic)
{
    if (APIC_EXFR_GET_LVT(apic_read(apic, APIC_REG_EXFR))) {

        int i;
        for (i = 0; i < APIC_EXFR_GET_LVT(apic_read(apic, APIC_REG_EXFR)); i++) {

            /* we assign a bogus vector to extended LVT entries */
            apic_write(apic, APIC_REG_EXTLVT(i), 0 | 
                    APIC_LVT_DISABLED | 
                    APIC_EXT_LVT_DUMMY_VEC);
        }
    }

}


static void
apic_dump (struct apic_dev * apic)
{
	char buf[128];

	APIC_DEBUG("DUMP (LOGICAL CPU #%u):\n", my_cpu_id());

	APIC_DEBUG(
		"  ID:  0x%08x (id=%d)\n",
		apic_read(apic, APIC_REG_ID),
		APIC_GET_ID(apic_read(apic, APIC_REG_ID))
	);

    APIC_DEBUG(
		"  VER: 0x%08x (version=0x%x, max_lvt=%d)\n",
		apic_read(apic, APIC_REG_LVR),
		APIC_LVR_VER(apic_read(apic, APIC_REG_LVR)),
		APIC_LVR_MAX(apic_read(apic, APIC_REG_LVR))
	);

    APIC_DEBUG(
        "  BASE ADDR: %p\n",
        apic->base_addr
    );

    if (nk_is_amd() && amd_has_ext_lvt(apic)) {
        APIC_DEBUG(
                "  EXT (AMD-only): 0x%08x (Ext LVT Count=%u, Ext APIC ID=%u, Specific EOI=%u, Int Enable Reg=%u)\n",
                apic_read(apic, APIC_REG_EXFR),
                APIC_EXFR_GET_LVT(apic_read(apic, APIC_REG_EXFR)),
                APIC_EXFR_GET_XAIDC(apic_read(apic, APIC_REG_EXFR)),
                APIC_EXFR_GET_SNIC(apic_read(apic, APIC_REG_EXFR)),
                APIC_EXFR_GET_INC(apic_read(apic, APIC_REG_EXFR))
                );

        int i;
        for (i = 0; i < APIC_EXFR_GET_LVT(apic_read(apic, APIC_REG_EXFR)); i++) {
            APIC_DEBUG(
                "      EXT-LVT[%u]: 0x%08x (%s)\n", 
                i,
                apic_read(apic, APIC_REG_EXTLVT(i)),
                lvt_stringify(apic_read(apic, APIC_REG_EXTLVT(i)), buf)
            );
        }
    }
        
    APIC_DEBUG(
		"  ESR: 0x%08x (Error Status Reg, non-zero is bad)\n",
		apic_read(apic, APIC_REG_ESR)
	);
    APIC_DEBUG(
		"  SVR: 0x%08x (Spurious vector=%d, %s, %s)\n",
		apic_read(apic, APIC_REG_SPIV),
		apic_read(apic, APIC_REG_SPIV) & APIC_SPIV_VEC_MASK,
		(apic_read(apic, APIC_REG_SPIV) & APIC_SPIV_SW_ENABLE)
			? "APIC IS ENABLED"
			: "APIC IS DISABLED",
        (apic_read(apic, APIC_REG_SPIV) & APIC_SPIV_CORE_FOCUS)
            ? "Core Focusing Disabled"
            : "Core Focusing Enabled"
	);

	/*
 	 * Local Vector Table
 	 */
	APIC_DEBUG("  Local Vector Table Entries:\n");
    char * timer_mode;
    if (apic_read(apic, APIC_REG_LVTT) & APIC_TIMER_PERIODIC) {
        timer_mode = "Periodic";
    } else if (apic_read(apic, APIC_REG_LVTT) & APIC_TIMER_TSCDLINE) {
        timer_mode = "TSC-Deadline";
    } else {
        timer_mode = "One-shot";
    }

	APIC_DEBUG("      LVT[0] Timer:     0x%08x (mode=%s, %s)\n",
		apic_read(apic, APIC_REG_LVTT),
        timer_mode,
		lvt_stringify(apic_read(apic, APIC_REG_LVTT), buf)
	);
	APIC_DEBUG("      LVT[1] Thermal:   0x%08x (%s)\n",
		apic_read(apic, APIC_REG_LVTTHMR),
		lvt_stringify(apic_read(apic, APIC_REG_LVTTHMR), buf)
	);
	APIC_DEBUG("      LVT[2] Perf Cnt:  0x%08x (%s)\n",
		apic_read(apic, APIC_REG_LVTPC),
		lvt_stringify(apic_read(apic, APIC_REG_LVTPC), buf)
	);
	APIC_DEBUG("      LVT[3] LINT0 Pin: 0x%08x (%s)\n",
		apic_read(apic, APIC_REG_LVT0),
		lvt_stringify(apic_read(apic, APIC_REG_LVT0), buf)
	);
	APIC_DEBUG("      LVT[4] LINT1 Pin: 0x%08x (%s)\n",
		apic_read(apic, APIC_REG_LVT1),
		lvt_stringify(apic_read(apic, APIC_REG_LVT1), buf)
	);
	APIC_DEBUG("      LVT[5] Error:     0x%08x (%s)\n",
		apic_read(apic, APIC_REG_LVTERR),
		lvt_stringify(apic_read(apic, APIC_REG_LVTERR), buf)
	);

	/*
 	 * APIC timer configuration registers
 	 */
	APIC_DEBUG("  Local APIC Timer:\n");
	APIC_DEBUG("      DCR (Divide Config Reg): 0x%08x\n",
		apic_read(apic, APIC_REG_TMDCR)
	);
	APIC_DEBUG("      ICT (Initial Count Reg): 0x%08x\n",
		apic_read(apic, APIC_REG_TMICT)
	);

	APIC_DEBUG("      CCT (Current Count Reg): 0x%08x\n",
		apic_read(apic, APIC_REG_TMCCT)
	);

	/*
 	 * Logical APIC addressing mode registers
 	 */
	APIC_DEBUG("  Logical Addressing Mode Information:\n");
	APIC_DEBUG("      LDR (Logical Dest Reg):  0x%08x (id=%d)\n",
		apic_read(apic, APIC_REG_LDR),
		GET_APIC_LOGICAL_ID(apic_read(apic, APIC_REG_LDR))
	);
	APIC_DEBUG("      DFR (Dest Format Reg):   0x%08x (%s)\n",
		apic_read(apic, APIC_REG_DFR),
		(apic_read(apic, APIC_REG_DFR) == APIC_DFR_FLAT) ? "FLAT" : "CLUSTER"
	);

	/*
 	 * Task/processor/arbitration priority registers
 	 */
	APIC_DEBUG("  Task/Processor/Arbitration Priorities:\n");
	APIC_DEBUG("      TPR (Task Priority Reg):        0x%08x\n",
		apic_read(apic, APIC_REG_TPR)
	);
	APIC_DEBUG("      PPR (Processor Priority Reg):   0x%08x\n",
		apic_read(apic, APIC_REG_PPR)
	);
	APIC_DEBUG("      APR (Arbitration Priority Reg): 0x%08x\n",
		apic_read(apic, APIC_REG_APR)
	);


    /* 
     * ISR/IRR
     */
    APIC_DEBUG("  IRR/ISR:\n");
    APIC_DEBUG("      IRR (Interrupt Request Reg):       0x%08x\n",
            apic_read(apic, APIC_GET_IRR(0)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_IRR(1)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_IRR(2)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_IRR(3)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_IRR(4)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_IRR(5)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_IRR(6)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_IRR(7)));

    APIC_DEBUG("      ISR (In-Service Reg):              0x%08x\n",
            apic_read(apic, APIC_GET_ISR(0)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_ISR(1)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_ISR(2)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_ISR(3)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_ISR(4)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_ISR(5)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_ISR(6)));
    APIC_DEBUG("                                         0x%08x\n",
            apic_read(apic, APIC_GET_ISR(7)));

}



void
apic_init (struct cpu * core)
{
    struct apic_dev * apic = NULL;
    ulong_t base_addr;
    uint32_t val;

    apic = (struct apic_dev*)malloc(sizeof(struct apic_dev));
    if (!apic) {
        panic("Could not allocate apic struct\n");
    }
    memset(apic, 0, sizeof(struct apic_dev));
    core->apic = apic;

    if (!check_apic_avail()) {
        panic("No APIC found on core %u, dying\n", core->id);
    } 

    /* In response to AMD erratum #663 
     * the damn thing may give us lint interrupts
     * even when we have them masked
     */
    if (nk_is_amd()  && cpuid_get_family() == 0x15) {
        APIC_DEBUG("Writing Bridge Ctrl MSR for AMD Errata #663\n");
        msr_write(AMD_MSR_NBRIDGE_CTL, 
                msr_read(AMD_MSR_NBRIDGE_CTL) | 
                (1ULL<<23) | 
                (1ULL<<54));
    }

    base_addr       = apic_get_base_addr();

    /* idempotent when not compiled as HRT */
    apic->base_addr = pa_to_va(base_addr);

#ifndef NAUT_CONFIG_HVM_HRT
    if (core->is_bsp) {
        /* map in the lapic as uncacheable */
        if (nk_map_page_nocache(apic->base_addr, PTE_PRESENT_BIT|PTE_WRITABLE_BIT, PS_4K) == -1) {
            panic("Could not map APIC\n");
        }
    }
#endif

    apic->version   = apic_get_version(apic);
    apic->id        = apic_get_id(apic);

#ifndef NAUT_CONFIG_XEON_PHI
    if (apic->version < 0x10 || apic->version > 0x15) {
        panic("Unsupported APIC version (0x%1x)\n", (unsigned)apic->version);
    }
#endif

    val = apic_read(apic, APIC_REG_LDR) & ~APIC_LDR_MASK;
    val |= SET_APIC_LOGICAL_ID(0);
    apic_write(apic, APIC_REG_LDR, val);

    apic_write(apic, APIC_REG_TPR, apic_read(apic, APIC_REG_TPR) & 0xffffff00);                       // accept all interrupts
    apic_write(apic, APIC_REG_LVTT,    APIC_DEL_MODE_FIXED | APIC_LVT_DISABLED);                      // disable timer interrupts intially
    apic_write(apic, APIC_REG_LVTPC,   APIC_DEL_MODE_FIXED | APIC_LVT_DISABLED | APIC_PC_INT_VEC);    // disable perf cntr interrupts
    apic_write(apic, APIC_REG_LVTTHMR, APIC_DEL_MODE_FIXED | APIC_LVT_DISABLED | APIC_THRML_INT_VEC); // disable thermal interrupts

    /* do we have AMD extended LVT entries to deal with */
    if (nk_is_amd() && amd_has_ext_lvt(apic)) {
        amd_setup_ext_lvt(apic);
    }
            

    /* mask 8259a interrupts */
    apic_write(apic, APIC_REG_LVT0, APIC_DEL_MODE_EXTINT  | APIC_LVT_DISABLED);

    /* only BSP takes NMI interrupts */
    apic_write(apic, APIC_REG_LVT1, 
            APIC_DEL_MODE_NMI | (core->is_bsp ? 0 : APIC_LVT_DISABLED));

    apic_write(apic, APIC_REG_LVTERR, APIC_DEL_MODE_FIXED | APIC_ERROR_INT_VEC); // allow error interrupts

    // clear the ESR
    apic_write(apic, APIC_REG_ESR, 0u);

    apic_global_enable();

    // assign interrupt handlers
    if (core->is_bsp) {

        if (register_int_handler(APIC_NULL_KICK_VEC, null_kick, apic) != 0) {
            panic("Could not register null kick interrupt handler\n");
        }

        if (register_int_handler(APIC_SPUR_INT_VEC, spur_int_handler, apic) != 0) {
            panic("Could not register spurious interrupt handler\n");
        }

        if (register_int_handler(APIC_ERROR_INT_VEC, error_int_handler, apic) != 0) {
            panic("Could not register spurious interrupt handler\n");
            return;
        }

        /* we shouldn't ever get these, but just in case */
        if (register_int_handler(APIC_PC_INT_VEC, pc_int_handler, apic) != 0) {
            panic("Could not register perf counter interrupt handler\n");
            return;
        }

        if (register_int_handler(APIC_THRML_INT_VEC, thermal_int_handler, apic) != 0) {
            panic("Could not register thermal interrupt handler\n");
            return;
        }

        if (register_int_handler(APIC_EXT_LVT_DUMMY_VEC, dummy_int_handler, apic) != 0) {
            panic("Could not register dummy ext lvt handler\n");
            return;
        }
    }

    apic_assign_spiv(apic, APIC_SPUR_INT_VEC);

    /* turn it on */
    apic_sw_enable(apic);

    /* pass in quantum as milliseconds */
#ifndef NAUT_CONFIG_XEON_PHI
    apic_timer_setup(apic, 1000/NAUT_CONFIG_HZ);
#endif

    apic_dump(apic);
}



void apic_set_oneshot_timer(struct apic_dev *apic, uint32_t ticks) 
{
    apic_write(apic, APIC_REG_LVTT, APIC_TIMER_ONESHOT | APIC_DEL_MODE_FIXED | APIC_TIMER_INT_VEC);
    apic_write(apic, APIC_REG_TMDCR, APIC_TIMER_DIVCODE);
    if (!ticks) {
	ticks=1; 
    }
    apic_write(apic, APIC_REG_TMICT, ticks);
    apic->current_ticks = ticks;
}

void apic_update_oneshot_timer(struct apic_dev *apic, uint64_t ticks,
			       nk_timer_condition_t cond)
{
    switch (cond) { 
    case UNCOND:
	apic_set_oneshot_timer(apic,ticks);
	break;
    case IF_EARLIER:
	if (ticks < apic->current_ticks) { apic_set_oneshot_timer(apic,ticks);}
	break;
    case IF_LATER:
	if (ticks > apic->current_ticks) { apic_set_oneshot_timer(apic,ticks);}
	break;
    }
}
	    



uint32_t apic_cycles_to_ticks(struct apic_dev *apic, uint64_t cycles)
{
    return cycles/apic->cycles_per_tick;
}

uint32_t apic_realtime_to_ticks(struct apic_dev *apic, uint64_t ns)
{
    return ((ns*1000)/apic->ps_per_tick);
}


uint64_t apic_realtime_to_cycles(struct apic_dev *apic, uint64_t ns)
{
    return apic_realtime_to_ticks(apic,ns)*apic->cycles_per_tick;
}


// this is 10 ms (1/100)
#define TEST_TIME_SEC_RECIP 100

static void calibrate_apic_timer(struct apic_dev *apic) 
{
    uint64_t start, end;
    uint16_t pit_count;
    uint8_t tmp2;

    // First determine the APIC's bus frequency by calibrating it
    // against a known clock (the PIT).   We do not know the base
    // rate of this APIC, but we do know the base rate of all PITs.
    // The PIT counts at about 1193180 Hz (~1.2 MHz)

    pit_count = 1193180 / TEST_TIME_SEC_RECIP;
    

    // Use APIC in one shot mode with the divider we will use 
    // in normal execution.  We will count down from a large number
    // and do not expect interrupts because it should not hit zero.
    apic_write(apic, APIC_REG_LVTT, APIC_TIMER_ONESHOT | APIC_DEL_MODE_FIXED | APIC_TIMER_INT_VEC);
    apic_write(apic, APIC_REG_TMDCR, APIC_TIMER_DIVCODE);

    // Now configure the PIT to count down the test period

    /* set PIT channel 2 to "out" mode */
    outb((inb(KB_CTRL_PORT_B) & 0xfd) | 0x1, 
          KB_CTRL_PORT_B);

    /* configure the PIT channel 2 for one-shot */  // 0x02 | 0x80 | 0x30 = > 10110010
    outb(PIT_MODE(PIT_MODE_ONESHOT) |
         PIT_CHAN(PIT_CHAN_SEL_2)   |
         PIT_ACC_MODE(PIT_ACC_MODE_BOTH),
         PIT_CMD_REG);

    /* LSB */ 
    outb(pit_count & 0xff,
	 PIT_CHAN2_DATA);

    // delay
    inb(KB_CTRL_DATA_OUT);

    /* MSB  */
    outb((uint8_t)(pit_count>>8),
	 PIT_CHAN2_DATA);

    /* clear and reset bit 0 of kbd ctrl port to reload
     * current cnt on chan 2 with the new value */
    tmp2 = inb(KB_CTRL_PORT_B) & 0xfe;
    outb(tmp2, KB_CTRL_PORT_B);
    outb(tmp2 | 1, KB_CTRL_PORT_B);

    // The PIT is now running, so we need to make the APIC start

    /* reset timer to our count down value */
    apic_write(apic, APIC_REG_TMICT, 0xffffffff);

/* TODO: need to calibrate timers with TSC on the Phi */

    start = rdtsc();
    // we are now waiting for the PIT to finish
    while (!(inb(KB_CTRL_PORT_B) & 0x20)) {
	// intentionally empty
    }
    end = rdtsc();

    // a known amount of real-time
    // has now finished

    /* stop the APIC timer */
    apic_write(apic, APIC_REG_LVTT, APIC_TIMER_DISABLE);

    // Now we have 1/TEST_TIME_SEC_RECIP seconds of real time in APIC timer ticks
    uint32_t apic_timer_ticks = 0xffffffff - apic_read(apic,APIC_REG_TMCCT) + 1;

    APIC_DEBUG("One test period (1/%u sec) took %u APIC ticks, pit_count=%u, and %lu cycles\n",
	       TEST_TIME_SEC_RECIP,apic_timer_ticks,(unsigned) pit_count, end-start);

    apic->bus_freq_hz = APIC_TIMER_DIV * apic_timer_ticks * TEST_TIME_SEC_RECIP;

    APIC_DEBUG("Detected APIC 0x%x bus frequency as %u Hz\n", apic->id, apic->bus_freq_hz);

    // picoseconds are used to try to keep precision
    apic->ps_per_tick = (1000000000000ULL / apic->bus_freq_hz) * APIC_TIMER_DIV;

    APIC_DEBUG("Detected APIC 0x%x real time per tick as %u ps\n", apic->id, apic->ps_per_tick);

    /////////////////////////////////////////////////////////////////
    // Now we will determine the calibration of the TSC to APIC time
    ////////////////////////////////////////////////////////////////

    const uint64_t num_trials = 50;
    uint64_t tsc_diff;
    uint64_t apic_diff;
    uint64_t scale_sum = 0;
    uint64_t scale_min = -1;
    uint64_t scale;

    int i = 0;

    extern void nk_simple_timing_loop(uint64_t iter_count);

    for (i = 0; i < num_trials; i++) {
	// set APIC for a long countdown time, longer than our test 
	apic_write(apic, APIC_REG_LVTT, APIC_TIMER_ONESHOT | APIC_DEL_MODE_FIXED | APIC_TIMER_INT_VEC);
	apic_write(apic, APIC_REG_TMDCR, APIC_TIMER_DIVCODE);
	// start it
	apic_write(apic, APIC_REG_TMICT, 0xffffffff);
	start = rdtsc();

	// now time a random amount of cycle burning
	// with both the tsc and the apic timer
	nk_simple_timing_loop(1000000);

	// now collect time using both
	end = rdtsc();
	apic_write(apic, APIC_REG_LVTT, APIC_TIMER_DISABLE);
	tsc_diff = (end - start);
	apic_diff = (0xffffffff - apic_read(apic, APIC_REG_TMCCT) + 1);
	
	scale = tsc_diff / apic_diff;
	scale_sum += scale;

	if (scale<scale_min) { 
	    scale_min=scale; 
	}
    }

    apic->cycles_per_tick = scale_sum/num_trials;

    APIC_DEBUG("Detected APIC 0x%x CPU cycles per tick as %lu cycles (min was %lu)\n", apic->id, apic->cycles_per_tick,scale_min);

}


static int apic_timer_handler(excp_entry_t * excp, excp_vec_t vec)
{
    struct apic_dev * apic = (struct apic_dev*)per_cpu_get(apic);
    uint64_t time_to_next_ns;

    // do all our callbacks

    time_to_next_ns = nk_timer_handler();

    // note that the low-level interrupt handler code in excp_early.S
    // takes care of invoking the scheduler if needed, and the scheduler
    // will in turn change the time after we leave - it may set the
    // timer to expire earlier

    apic_set_oneshot_timer(apic,apic_realtime_to_ticks(apic,time_to_next_ns));
    
    IRQ_HANDLER_END();
    
    return 0;
}
