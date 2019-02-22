# Pisces port notes

This is the current state of the Nautilus + Pisces port.

## General status

This pisces branch of Nautilus currently has relevant code in:
    - `src/arch/pisces`
    - `include/arch/pisces`

There's really nothing special going on (yet) other than the custom linker script (`link/nautilus.ld.pisces`) 
and the entry point to the kernel (`pisces_boot_start` in `src/arch/pisces/asm/boot.S`).

Nautilus kernel main (`src/arch/pisces/main.c` and `src/arch/pisces/init.c`) is not yet even invoked. Rather, 
the bootstrap code calls into C via a small piece of test code in `src/arch/pisces/test.c`, which I was using to iron out
issues with the pisces console. Be warned, that code is a real mess currently.


## KCH dev. env. 

This was being tested on physical hardware:
- HP ProLiant DL320e Gen8 v2
- Quad-core (8 thread) Xeon E3-1270v3 @ 3.5GHz
- 8GB RAM, 1 NUMA node
- Linux kernel 3.14.2-200 (Fedora 20)

## Building

Make sure to build nautilus with Pisces as the target arch. via `make menuconfig`. Then to build the kernel binary:

```
[you@you] make
```

The extra step for Pisces is to strip the kernel binary using `objcopy`. You can do this manually or run:

```
[you@you] scripts/pisces_gen_raw_img.sh
```

You should be able to then load as in standard Pisces:

```
[you@you] pisces_load nautilus.raw nautilus.bin “console=pisces” 
```
Nautilus doesn't need an initramfs, so the `nautilus.bin` here is just a placeholder. Console option isn't needed either really.

Launch:

```
[you@you] pisces_launch /dev/pisces-enclaveN 
```

where `N` is some number >= 0.

Console:

```
[you@you] pisces_cons /dev/pisces-enclaveN
```


# Porting Notes
The current state is that we can boot Nautilus fine, but output is borked due to some issue with how the binary is being
loaded, particularly `.rodata`. See below for more information.

## Historical notes:

### First stab:
    - Fixed issue with init page table installation. There were 2 major bugs. (1) the PD initialization loop was adding the load delta to the page address every iteration of the loop. (2) When we installed the identity + offset page tables, the next ifetch would fail since it would be at 0x8000000 something, which would now map to 0x800000 + delta. So offset mapping *everything* was not the right way to go. Instead, we only offset map the pages where kernel code /data expects to be. This turns out to be the pages corresponding to 2MB -> 6MB. So only 2 PD entries need to be offset mapped. Everything else is identity mapped.
    - Got into C code with an initial boot stack. We can keep talking to the debug buffer in the boot params structure (by setting the first character), and we can notify pisces that we’ve booted (so `pisces_launch` actually succeeds now).
	- Still can’t seem to write to the pisces console. Something is going on where if I use `pisces_console_write`, the argument address is getting borked to point to some other string in `.rodata`. Not sure what’s happening here, perhaps the Linux loader is doing something special for strings? (See below)

### Second stab:
`0x434b6f` = address of string to print

`0x43546e` = what actually is printed

Difference between the string and what’s printed is fixed at `0x900`, strangely
non-random. It’s higher in memory than it should be.  Doesn’t seem to be
a memory translation issue, as I can copy bytes directly into the debug buffer
and see things show up as expected. Turns out the Linux bootloader is loading
`.rodata` `0x900` earlier than it should. Why? `.text` and `.data` seem to be
fine.

Figured this out by getting the linker to prepend an 8-byte magic cookie to
`.rodata`, then scanning that in Nautilus to find out where it _actually_ was
being loaded. You can see this in the linker script (`link/nautilus.ld.pisces`).
