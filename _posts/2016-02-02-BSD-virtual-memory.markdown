---
published: false
title: BSD Virtual Memory
layout: post
tags: [OS, unix, BSD, memory]
---
After [the article on POSIX memory management](/2016/02/01/posix-memory-management/), we have a good grasp of the high-level memory allocation functions specified in [POSIX.1](http://pubs.opengroup.org/onlinepubs/9699919799/).  We learned how `malloc` is a C library function which can be implemented using `mmap`.  Now it's time to dive into the details about how `mmap` is implemented.  

Under the hood, `mmap` touches a fundamental concept in operating systems.  Specifically, it must interface with the kernel's implementation of virtual memory.  Virtual memory is the way in which we give each process the illusion that it is the only running process and it has full access to the system's memory.

There are 3 main ways to virtualize memory: segmentation, paging, and swapping.  Segmentation builds on the concept we touched on in [the previous article](/2016/02/01/posix-memory-management/), that each process is split into several "segments," such as heap, stack and text.  These segments can be placed independently in physical memory and with hardware support their virtual addresses could be translated to physical ones.  However, keeping these segments contiguous in memory can be a lot of overhead.  For that reason, paging divides virtual memory into fixed-size pages, which are placed independently in fixed-size frames in physical memory.  Finally, swapping moves allocated but inactive parts of memory to disk to free up space for active processes.

POSIX.1 doesn't specify implementation details, so we have to pick a particular operating system to investigate.  For no particularly good reason, we're going with BSD, and we'll be looking at NetBSD and FreeBSD in particular.  We'll be looking at those two BSDs in particular for historical reasons, so it's worth taking a brief aside to go over that history.

# BSD History

UNIX was started at Bell Labs in 1969.  In 1974, the University of California at Berkeley received a copy of UNIX which they ran on a PDP-11.  In 1975, they installed UNIX v6.  By 1977, they had written enough software in which other Universities were interested that they started bundling it together as 1BSD.  

In 1978, a VAX computer was installed at Berkeley, and though the original UNIX for the PDP-11 supported paging and swapping, the UNIX version ported to this machine, UNIX/32V, was released without paging.  So 2BSD included a largely rewritten kernel for the VAX which included support for paging.

In 1985, a group at Carnegie Mellon University began work on a research kernel called Mach that would replace the BSD kernel.  Importantly, Mach was designed to be platform-independent (as opposed to all previous versions of BSD or UNIX).  This decision likely led to the good kernel design that inspired the design of several future BSD variants.

In 1988, the decision was finally made to move BSD away from VAX and cleanly separate its machine-dependent and machine-independent code.  4.3BSD-Tahoe was the interrim BSD release for the Power 6/32 platform which put this into practice, though the port for that platform was very quickly abandoned.

Also in 1988, the Single UNIX Specification officially became the first version of POSIX, IEEE 1003.1-1988.

By 1989, much of BSD relied on proprietary UNIX code which relied on having an AT&T software license, which was becoming increasingly expensive.  Thus began an effort to rewrite all the proprietary dependencies which became BSD Net/1.

In 1990, 4.3BSD-Reno, another interrim version, was released which pushed towards POSIX compliance.  By 1991, most of the AT&T code had been replaced, and Net/2 was released.  Net/2 used the VM system from Mach 2.5.

In 1992, 4.3BSD-Reno and Net/2 were used as the basis of a port to the Intel 386 processor, which was called 386BSD.  Notably, this finally replaced all the proprietary code that was still left in Net/2.

In 1993, 386BSD was forked into FreeBSD and NetBSD.  By 1994, 386BSD was abandoned.  Also, the AT&T lawsuit was resolved, and 4.4BSD-Lite was released, containing no AT&T source code.  This release incorporated many of Mach's design decisions and were largely adopted by both FreeBSD and NetBSD over the following years.  In 1996, NetBSD was forked into OpenBSD.

In 1998, Charles Cranor wrote a dissertation on the design of UVM, a virtual memory system which was to replace Mach's in NetBSD.  Much of this was also ported to OpenBSD.

In 2004, version 4.8 of FreeBSD was forked into DragonFly BSD.

# Virtual Memory Systems

So finally, we can talk about virtual memory systems.  We can summarize the above by saying that there are 2 main BSD variants today: FreeBSD and NetBSD.  Each of which has its own variant: DragonFly BSD and OpenBSD, respectively.  FreeBSD and DragonFly BSD have virtual memory systems based on Mach (or 4.4BSD-Lite if you prefer), and NetBSD and OpenBSD have virtual memory systems based on UVM.

## FreeBSD (Mach)

### Data Structures

The FreeBSD kernel stores address space information about each process in a `vmspace` structure, which encapsulates both machine-dependent and machine-independent information.  We describe here only the machine-independent data structures.  Each `vmspace` structure contains a `vm_map` structure, which points to an ordered linked-list of `vm_map_entry` structure objects.

Each `vm_map_entry` describes a contiguous region of virtual memory and contains a pointer to a next entry, and to a chain of `vm_object` structures.  Each contiguous region of virtual memory pointed to by a `vm_map_entry` has the same attributes (such as protection), so these are also stored in this structure.  Between a `vm_map_entry` and its chain of `vm_object`s, there are zero or more "shadow" `vm_object`s which track changes to the `vm_object`, each of which stores a pointer to a `vm_page` containing the changes and another pointer to the unmodified `vm_object`.

A `vm_object` structure contains a pointer to another linked list of `vm_page` structures which represent the physical memory cache of the `vm_object`.  The `vm_page` also keeps a radix tree of these `vm_page` structures (keyed by its logical offset from the start of the `vm_object`).  This radix tree makes searching for `vm_page` structures much quicker.

### DragonFly BSD Changes

A notable difference between DragonFly BSD and FreeBSD is that the former also stores the `vm_map_entry` structures in a tree.

## NetBSD and OpenBSD (UVM)

UVM was based on 4.4BSD which itself was based on Mach, and so it initially bares some resemblance to the virtual memory system in FreeBSD.  However, UVM was designed to support memory sharing using three mechanisms: page loanout, page transfer, and map entry passing.

Page loanout is when a process loans its memory to another process.  This is useful particularly in networking, in which data can be sent to the kernel's network stack simply by loaning the appropriate pages.  This avoids the need for costly copy operations.

Page transfer is similar to loanout, except the pages remain in the possession of the receiving process.

Map entry passing, rather than transfering the pages of virtual memory, copies the higher-level map objects in order to export a large range of memory to another process.  This saves nothing when copying a single page, but scales very well since a map object can point to very many pages in memory, and only the map structure itself need be copied.

### Data Structures

UVM is designed with `vmspace`, `vm_map`, `vm_object`, and `vm_page` objects which function similarly to those in FreeBSD.  We will describe the differences.

In addition to what was described above, each `vm_object` has a `vm_pager` object which describes how the backing store can be accessed.  Essentially, this is a pointer to a list of functions which fetch and store pages between the memory pointed to by the `vm_page` object and whatever backing store (such as a disk) underlies the `vm_object`.



# References

I referred heavily to the Wikipedia entries on Unix, BSD, and Mach.  For the section on FreeBSD, I referred to "The Design and Implementation of FreeBSD."  For the section on NetBSD and OpenBSD, I referred to Charles Cranor's dissertation "Design and Implementation of the UVM Virtual Memory System."
