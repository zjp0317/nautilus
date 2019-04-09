#include <nautilus/nautilus.h>
#include <arch/pisces/pisces_boot_params.h>

extern int pisces_console_init(void);

extern void pisces_cons_write (const char *str);
extern ulong_t __rodata_start;

void pisces_go (uint64_t param_pg_no);
void pisces_go (uint64_t param_pg_no)
{
    pisces_boot_params = (struct pisces_boot_params*)(param_pg_no << 12);

    const char* x = "hello from nautilus\n";
    pisces_boot_params->initialized = 1;

    pisces_console_init();

    //*(uint64_t*)((uint64_t) pisces_boot_params->init_dbg_buf + 8) = (uint64_t)(&__rodata_start);

    if (*(uint64_t*)(&__rodata_start) != 0x00000000deadbeef) {
        pisces_boot_params->init_dbg_buf[0] = 'e';
        pisces_boot_params->init_dbg_buf[1] = 'r';
        pisces_boot_params->init_dbg_buf[2] = 'r';
    } else {
        pisces_boot_params->init_dbg_buf[0] = 'O';
        pisces_boot_params->init_dbg_buf[1] = 'K';
    }

#if 0
    uint64_t * a = (uint64_t*)0x200000;

    for (a; a < (uint64_t*)0x600000; a++) {
        if (*a == 0x00000000deadbeef) {
            *(uint64_t*)((uint64_t) pisces_boot_params->init_dbg_buf + 8) = (uint64_t)a;
        }
    }
#endif

    *(uint64_t*)((uint64_t) pisces_boot_params->init_dbg_buf + 8) = (uint64_t)x;

    pisces_cons_write(x);


    while (1);
}
