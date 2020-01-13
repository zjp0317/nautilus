/* Console Driver when Kitten is running as a multi-instance guest on pisces
 * Jiannan Ouyang (ouyang@cs.pitt.edu)
 */

#include <nautilus/nautilus.h>
#include <nautilus/naut_types.h>
#include <arch/pisces/pisces_boot_params.h>
#include "pisces_lock.h"

// Embedded ringbuffer that maps into a 64KB chunk of memory
struct pisces_cons_ringbuf {
    struct pisces_spinlock lock;
    uint64_t read_idx;
    uint64_t write_idx;
    uint64_t cur_len;
    uint8_t buf[(128 * 1024) - 32];
    //uint8_t buf[(64 * 1024) - 32];
} __attribute__((packed));


static struct pisces_cons_ringbuf * console_buffer = NULL;


/** Set when the console has been initialized. */
static int initialized = 0;


#define USE_NK_LOCK 0 //1

#if USE_NK_LOCK
spinlock_t console_lock;
#endif
/**
 * Prints a single character to the pisces console buffer.
 */
void pisces_cons_putc(unsigned char c)
{
#if USE_NK_LOCK
    int flags = spin_lock_irq_save(&console_lock);
#else
	pisces_spin_lock(&(console_buffer->lock));
#endif

	// If the buffer is full, then we are just going to start overwriting the log
	console_buffer->buf[console_buffer->write_idx] = c;

	console_buffer->cur_len++;
	console_buffer->write_idx++;
	console_buffer->write_idx %= sizeof(console_buffer->buf);
	
	if (console_buffer->cur_len > sizeof(console_buffer->buf)) {
		// We are overwriting, update the read state to be sane
		console_buffer->read_idx++;
		console_buffer->read_idx %= sizeof(console_buffer->buf);
		console_buffer->cur_len--;
	}

#if USE_NK_LOCK
    spin_unlock_irq_restore(&console_lock,flags);
#else
	pisces_spin_unlock(&(console_buffer->lock));
#endif

}


/**
 * Reads a single character from the pisces console port.
 */
/*
static char pisces_cons_getc(struct console *con)
{
    u64 *cons, *prod;
    char c;

    cons = &console_buffer->in_cons;
    prod = &console_buffer->in_prod;

    pisces_spin_lock(&console_buffer->lock_out);
    c = console_buffer->in[*cons];
    *cons = (*cons + 1) % PISCES_CONSOLE_SIZE_IN; 
    pisces_spin_unlock(&console_buffer->lock_out);


    return c;
}
*/

/**
 * Writes a string to the pisces console buffer.
 */
void pisces_cons_write (const char *str);
void pisces_cons_write (const char *str)
{	
	unsigned char c;
    int cnt = 0;

	while ((c = *str++) != '\0') {
		pisces_cons_putc(c);
        cnt = (cnt + 1) % 8;
	}
}

/**
 * Initializes and registers the pisces console driver.
 */
int pisces_console_init(void);
int 
pisces_console_init(void) 
{
    if (initialized) {
        printk("Pisces console already initialized.\n");
        return -1;
    }

    console_buffer = (struct pisces_cons_ringbuf*)pisces_boot_params->console_ring_addr; 

    initialized = 1;

    return 0;
}

