# Pisces port notes

 Should load like this:
```
 pisces_load nautilus.raw nautilus.bin “console=pisces” (here the nautilus.bin is a standin for initrd, and console isn’t really needed)
```
 Launch:
```
 pisces_launch /dev/pisces-enclaveN where N is some number >= 0
```
 Console:
```
 pisces_cons /dev/pisces-enclaveN
```

## Porting Notes

Actually this may be simpler than I thought. The Linux bootloader doesn’t care about the image. It just jumps to it. As long as it’s executable code we should be fine. We just either have to set rip appropriately in pisces or strip the ELF data:

```
vmlwk.bin: vmlwk
    $(OBJCOPY) -O binary $< $@
```

`startup_64` in kitten (`arch/x86_64/kernel/head.S`) is the place to look for boot code examples.

### First stab:
    - Fixed issue with init page table installation. There were 2 major bugs. (1) the PD initialization loop was adding the load delta to the page address every iteration of the loop. (2) When we installed the identity + offset page tables, the next ifetch would fail since it would be at 0x8000000 something, which would now map to 0x800000 + delta. So offset mapping *everything* was not the right way to go. Instead, we only offset map the pages where kernel code /data expects to be. This turns out to be the pages corresponding to 2MB -> 6MB. So only 2 PD entries need to be offset mapped. Everything else is identity mapped.
    - Got into C code with an initial boot stack. We can keep talking to the debug buffer in the boot params (by setting the first character), and we can notify pisces that we’ve booted (so `pisces_launch` actually succeeds now).
	- Still can’t seem to write to the pisces console. Something is going on where if I use `pisces_console_write`, the argument address is getting borked to point to some other string in .rodata. Not sure what’s happening here, perhaps the Linux loader is doing something special for strings??

### Second stab:
0x434b6f = address of string to print

0x43546e = what actually is printed

Difference between the string and what’s printed is `0x900`, strangely non-random. It’s higher in memory than it should be.
Doesn’t seem to be a memory translation issue, as I can copy the bytes directly into the debug buffer
Turns out the Linux bootloader is loading `.rodata` 0x900 earlier than it should. Why? `.text` and `.data` seem to be fine.
