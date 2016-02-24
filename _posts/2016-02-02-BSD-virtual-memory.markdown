---
published: true
title: BSD Virtual Memory
layout: post
tags: [OS, unix, BSD, memory]
---
After [the article on POSIX memory management](/2016/02/01/posix-memory-management/), we have a good grasp of the high-level memory allocation functions specified in [POSIX.1](http://pubs.opengroup.org/onlinepubs/9699919799/).  We learned how `malloc` is a C library function which can be implemented using `mmap`.  Now it's time to dive into the details about how `mmap` is implemented.  

Under the hood, `mmap` touches a fundamental concept in operating systems.  Specifically, it must interface with the kernel's implementation of virtual memory.  Virtual memory is the way in which we give each process the illusion that it is the only running process and it has full access to the system's memory.

There are 3 main ways to virtualize memory: segmentation, paging, and swapping.  Segmentation builds on the concept we touched on in [the previous article](/2016/02/01/posix-memory-management/), that each process is split into several "segments," such as heap, stack and text.  These segments can be placed independently in physical memory and with hardware support their virtual addresses could be translated to physical ones.  However, keeping these segments contiguous in memory can be a lot of overhead.  For that reason, paging divides virtual memory into fixed-size pages, which are placed independently in fixed-size frames in physical memory.  Finally, swapping moves allocated but inactive parts of memory to disk to free up space for active processes.

POSIX.1 doesn't specify implementation details, so we have to pick a particular operating system to investigate.  For no particularly good reason, we're going with BSD, and we'll be looking at NetBSD and FreeBSD in particular.  We'll be looking at those two BSDs in particular for historical reasons, so it's worth taking a brief aside to go over that history.

# BSD History

[UNIX was started at Bell Labs in 1969.](https://en.wikipedia.org/wiki/Unix)  In 1974, the University of California at Berkeley received a copy of UNIX which they ran on a [PDP-11](https://en.wikipedia.org/wiki/PDP-11).  In 1975, they installed UNIX v6.  By 1977, they had written enough software in which other Universities were interested that they started bundling it together as [1BSD](https://en.wikipedia.org/wiki/Berkeley_Software_Distribution).  

In 1978, a [VAX computer](https://en.wikipedia.org/wiki/VAX-11) was installed at Berkeley, and though the original UNIX for the PDP-11 supported paging and swapping, the UNIX version ported to this machine, UNIX/32V, was released without paging.  So 2BSD included a largely rewritten kernel for the VAX which included support for paging.

In 1985, a group at Carnegie Mellon University began work on [a research kernel called Mach](https://en.wikipedia.org/wiki/Mach_%28kernel%29) that would replace the BSD kernel.  Importantly, Mach was designed to be platform-independent (as opposed to all previous versions of BSD or UNIX).  This decision likely led to the good kernel design that inspired the design of several future BSD variants.

In 1988, the decision was finally made to move BSD away from VAX and cleanly separate its machine-dependent and machine-independent code.  4.3BSD-Tahoe was the interrim BSD release for the Power 6/32 platform which put this into practice, though the port for that platform was very quickly abandoned.

Also in 1988, the [Single UNIX Specification](https://en.wikipedia.org/wiki/Single_UNIX_Specification) officially became the first version of [POSIX, IEEE 1003.1-1988](https://en.wikipedia.org/wiki/POSIX).

By 1989, much of BSD relied on proprietary UNIX code which relied on having an AT&T software license, which was becoming increasingly expensive.  Thus began an effort to rewrite all the proprietary dependencies which became BSD Net/1.

In 1990, 4.3BSD-Reno, another interrim version, was released which pushed towards POSIX compliance.  By 1991, most of the AT&T code had been replaced, and Net/2 was released.  Net/2 used the VM system from Mach 2.5.

[In 1992, 4.3BSD-Reno and Net/2 were used as the basis of a port to the Intel 386 processor, which was called 386BSD.  Notably, this finally replaced all the proprietary code that was still left in Net/2.](http://porting-unix-to-the-386.jolix.com/)  Also in 1992, [BSD/386](https://en.wikipedia.org/wiki/BSD/OS), a commercial port to the 386, was also released, but even before its release AT&T filed a lawsuit against them for breach of their copyright.

In 1993, 386BSD was forked into [FreeBSD](https://en.wikipedia.org/wiki/FreeBSD) and [NetBSD](https://en.wikipedia.org/wiki/NetBSD).  By 1994, 386BSD was abandoned.  Also, the AT&T lawsuit was resolved, and 4.4BSD-Lite was released, containing no AT&T source code.  This release incorporated many of Mach's design decisions and were largely adopted by both FreeBSD and NetBSD over the following years.  In 1996, NetBSD was forked into [OpenBSD](https://en.wikipedia.org/wiki/OpenBSD).

In 1998, [Charles Cranor wrote a dissertation](http://chuck.cranor.org/p/diss.pdf) on the design of [UVM](http://www.netbsd.org/docs/kernel/uvm.html), a virtual memory system which was to replace Mach's in NetBSD.  Much of this was also ported to OpenBSD.

In 2004, version 4.8 of FreeBSD was forked into [DragonFly BSD](https://en.wikipedia.org/wiki/DragonFly_BSD).

# Virtual Memory Systems

So finally, we can talk about virtual memory systems.  We can summarize the above by saying that there are 2 main BSD variants today: FreeBSD and NetBSD.  Each of which has its own sub-variant: DragonFly BSD and OpenBSD, respectively.  FreeBSD and DragonFly BSD have virtual memory systems based on Mach (or 4.4BSD-Lite if you prefer), and NetBSD and OpenBSD have virtual memory systems based on UVM.

## FreeBSD (Mach)

### Data Structures

![](http://www.pr4tt.com/wiki/lib/exe/fetch.php?media=freebsd_virtual_memory.gif)

The FreeBSD kernel stores address space information about each process in a `vmspace` structure, which encapsulates both machine-dependent and machine-independent information.  We describe here only the machine-independent data structures.  Each `vmspace` structure contains a `vm_map` structure, which points to an ordered linked-list of `vm_map_entry` structure objects.

Each `vm_map_entry` describes a contiguous region of virtual memory and contains a pointer to a next entry, and to a chain of `vm_object` structures.  Each contiguous region of virtual memory pointed to by a `vm_map_entry` has the same attributes (such as protection), so these are also stored in this structure.  Between a `vm_map_entry` and its chain of `vm_object`s, there are zero or more "shadow" `vm_object`s which track changes to the `vm_object`, each of which stores a pointer to a `vm_page` containing the changes and another pointer to the unmodified `vm_object`.

A `vm_object` structure contains a pointer to another linked list of `vm_page` structures which represent the physical memory cache of the `vm_object`.  The `vm_page` also keeps a radix tree of these `vm_page` structures (keyed by its logical offset from the start of the `vm_object`).  This radix tree makes searching for `vm_page` structures much quicker.

### DragonFly BSD Changes

A notable difference between DragonFly BSD and FreeBSD is that the former also stores the `vm_map_entry` structures in a tree.

## NetBSD and OpenBSD (UVM)

<img src="http://www.pr4tt.com/wiki/lib/exe/fetch.php?media=uvm.gif" style="width: 100%" />

UVM was based on 4.4BSD which itself was based on Mach, and so it initially bares some resemblance to the virtual memory system in FreeBSD.  However, UVM was designed to support memory sharing using three mechanisms: page loanout, page transfer, and map entry passing.

Page loanout is when a process loans its memory to another process.  This is useful particularly in networking, in which data can be sent to the kernel's network stack simply by loaning the appropriate pages.  This avoids the need for costly copy operations.

Page transfer is similar to loanout, except the pages remain in the possession of the receiving process.

Map entry passing, rather than transfering the pages of virtual memory, copies the higher-level map objects in order to export a large range of memory to another process.  This saves nothing when copying a single page, but scales very well since a map object can point to very many pages in memory, and only the map structure itself need be copied.

### Data Structures

UVM is designed with `vmspace`, `vm_map`, `vm_object`, and `vm_page` objects which function similarly to those in FreeBSD.  We will describe the differences.

In addition to what was described above, each `vm_object` has a `vm_pager` object which describes how the backing store can be accessed.  Essentially, this is a pointer to a list of functions which fetch and store pages between the memory pointed to by the `vm_page` object and whatever backing store (such as a disk) underlies the `vm_object`.

### Implementation

It's interesting to look at the implementation to see all the gory details.  We can find the definition of the `mmap` system call for OpenBSD in [their CVS repo in `src/sys/uvm/uvm_mmap.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_mmap.c?rev=1.122&content-type=text/x-cvsweb-markup).  In fact, there are too many gory details here, so I will show a version here with lots of extra stuff cut out.  We only really care about the case where extra anonymous memory is allocated.

{% highlight C %}
/*
 * sys_mmap: mmap system call.
 *
 * => file offset and address may not be page aligned
 *    - if MAP_FIXED, offset and address must have remainder mod PAGE_SIZE
 *    - if address isn't page aligned the mapping starts at trunc_page(addr)
 *      and the return value is adjusted up by the page offset.
 */
int
sys_mmap(struct proc *p, void *v, register_t *retval)
{
	/* ... */

	/* first, extract syscall args from the uap. */
	/* ... */

	/* validate the flags */
	/* ... */

	error = pledge_protexec(p, prot);
	if (error)
		return (error);

	/* align file position and save offset.  adjust size. */
	ALIGN_ADDR(pos, size, pageoff);

	/* now check (MAP_FIXED) or get (!MAP_FIXED) the "addr" */
	if (flags & MAP_FIXED) {
		/* ... */

	}

	/* check for file mappings (i.e. not anonymous) and verify file. */
	if ((flags & MAP_ANON) == 0) {
	/* ... */
	} else {		/* MAP_ANON case */
		/*
		 * XXX What do we do about (MAP_SHARED|MAP_PRIVATE) == 0?
		 */
		if (fd != -1)
			return EINVAL;

is_anon:	/* label for SunOS style /dev/zero */

		if ((flags & MAP_ANON) != 0 ||
		    ((flags & MAP_PRIVATE) != 0 && (prot & PROT_WRITE) != 0)) {
			if (size >
			    (p->p_rlimit[RLIMIT_DATA].rlim_cur - ptoa(p->p_vmspace->vm_dused))) {
				return ENOMEM;
			}
		}
		maxprot = PROT_MASK;
		error = uvm_mmapanon(&p->p_vmspace->vm_map, &addr, size, prot, maxprot,
		    flags, p->p_rlimit[RLIMIT_MEMLOCK].rlim_cur, p);
	}

	if (error == 0)
		/* remember to add offset */
		*retval = (register_t)(addr + pageoff);

	/* ... */
	return (error);
}
{% endhighlight %}

And `uvm_mmapanon` is defined in the same file:

{% highlight C %}
/*
 * uvm_mmapanon: internal version of mmap for anons
 *
 * - used by sys_mmap
 */
int
uvm_mmapanon(vm_map_t map, vaddr_t *addr, vsize_t size, vm_prot_t prot,
    vm_prot_t maxprot, int flags, vsize_t locklimit, struct proc *p)
{
	int error;
	int advice = MADV_NORMAL;
	unsigned int uvmflag = 0;
	vsize_t align = 0;	/* userland page size */

	/*
	 * for non-fixed mappings, round off the suggested address.
	 * for fixed mappings, check alignment and zap old mappings.
	 */
	if ((flags & MAP_FIXED) == 0) {
		*addr = round_page(*addr);	/* round */
	} else {
		if (*addr & PAGE_MASK)
			return(EINVAL);

		uvmflag |= UVM_FLAG_FIXED;
		if ((flags & __MAP_NOREPLACE) == 0)
			uvmflag |= UVM_FLAG_UNMAP;
	}

	if ((flags & MAP_FIXED) == 0 && size >= __LDPGSZ)
		align = __LDPGSZ;
	if ((flags & MAP_SHARED) == 0)
		/* XXX: defer amap create */
		uvmflag |= UVM_FLAG_COPYONW;
	else
		/* shared: create amap now */
		uvmflag |= UVM_FLAG_OVERLAY;

	/* set up mapping flags */
	uvmflag = UVM_MAPFLAG(prot, maxprot,
	    (flags & MAP_SHARED) ? MAP_INHERIT_SHARE : MAP_INHERIT_COPY,
	    advice, uvmflag);

	error = uvm_mapanon(map, addr, size, align, uvmflag);

	if (error == 0)
		error = uvm_mmaplock(map, addr, size, prot, locklimit);
	return error;
}
{% endhighlight %}

The function prototype for `uvm_mapanon` is in `src/sys/uvm/uvm_extern.h` but [its definition is in `src/sys/uvm/uvm_map.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_map.c?rev=1.205&content-type=text/x-cvsweb-markup):

{% highlight C %}
/*
 * uvm_mapanon: establish a valid mapping in map for an anon
 *
 * => *addr and sz must be a multiple of PAGE_SIZE.
 * => *addr is ignored, except if flags contains UVM_FLAG_FIXED.
 * => map must be unlocked.
 *
 * => align: align vaddr, must be a power-of-2.
 *    Align is only a hint and will be ignored if the alignment fails.
 */
int
uvm_mapanon(struct vm_map *map, vaddr_t *addr, vsize_t sz,
    vsize_t align, unsigned int flags)
{
	/* ... */

	/*
	 * Before grabbing the lock, allocate a map entry for later
	 * use to ensure we don't wait for memory while holding the
	 * vm_map_lock.
	 */
	new = uvm_mapent_alloc(map, flags);
	if (new == NULL)
		return(ENOMEM);
	
	/* ... */

	/*
	 * Create new entry.
	 * first and last may be invalidated after this call.
	 */
	entry = uvm_map_mkentry(map, first, last, *addr, sz, flags, &dead,
	    new);
	if (entry == NULL) {
		error = ENOMEM;
		goto unlock;
	}
	new = NULL;
	KDASSERT(entry->start == *addr && entry->end == *addr + sz);
	entry->object.uvm_obj = NULL;
	entry->offset = 0;
	entry->protection = prot;
	entry->max_protection = maxprot;
	entry->inheritance = inherit;
	entry->wired_count = 0;
	entry->advice = advice;
	if (flags & UVM_FLAG_NOFAULT)
		entry->etype |= UVM_ET_NOFAULT;
	if (flags & UVM_FLAG_COPYONW) {
		entry->etype |= UVM_ET_COPYONWRITE;
		if ((flags & UVM_FLAG_OVERLAY) == 0)
			entry->etype |= UVM_ET_NEEDSCOPY;
	}
	if (flags & UVM_FLAG_OVERLAY) {
		KERNEL_LOCK();
		entry->aref.ar_pageoff = 0;
		entry->aref.ar_amap = amap_alloc(sz,
		    ptoa(flags & UVM_FLAG_AMAPPAD ? UVM_AMAP_CHUNK : 0),
		    M_WAITOK);
		KERNEL_UNLOCK();
	}

	/* Update map and process statistics. */
	map->size += sz;
	((struct vmspace *)map)->vm_dused += uvmspace_dused(map, *addr, *addr + sz);

unlock:
	vm_map_unlock(map);

	/*
	 * Remove dead entries.
	 *
	 * Dead entries may be the result of merging.
	 * uvm_map_mkentry may also create dead entries, when it attempts to
	 * destroy free-space entries.
	 */
	uvm_unmap_detach(&dead, 0);
out:
	if (new)
		uvm_mapent_free(new);
	return error;
}
{% endhighlight %}

So that largely defers to `uvm_map_mkentry`, which is again defined in the same file.

{% highlight C %}
/*
 * Create and insert new entry.
 *
 * Returned entry contains new addresses and is inserted properly in the tree.
 * first and last are (probably) no longer valid.
 */
struct vm_map_entry*
uvm_map_mkentry(struct vm_map *map, struct vm_map_entry *first,
    struct vm_map_entry *last, vaddr_t addr, vsize_t sz, int flags,
    struct uvm_map_deadq *dead, struct vm_map_entry *new)
{
	/* ... */

	/* Initialize new entry. */
	if (new == NULL)
		entry = uvm_mapent_alloc(map, flags);
	else
		entry = new;
	if (entry == NULL)
		return NULL;
	/* ... */
	return entry;
}
{% endhighlight %}

Again, `uvm_mapent_alloc` is in the same file.

{% highlight C %}
/*
 * uvm_mapent_alloc: allocate a map entry
 */
struct vm_map_entry *
uvm_mapent_alloc(struct vm_map *map, int flags)
{
	struct vm_map_entry *me, *ne;
	int pool_flags;
	int i;

	pool_flags = PR_WAITOK;
	if (flags & UVM_FLAG_TRYLOCK)
		pool_flags = PR_NOWAIT;

	if (map->flags & VM_MAP_INTRSAFE || cold) {
		mtx_enter(&uvm_kmapent_mtx);
		me = uvm.kentry_free;
		if (me == NULL) {
			ne = km_alloc(PAGE_SIZE, &kv_page, &kp_dirty,
			    &kd_nowait);
			if (ne == NULL)
				panic("uvm_mapent_alloc: cannot allocate map "
				    "entry");
			for (i = 0;
			    i < PAGE_SIZE / sizeof(struct vm_map_entry) - 1;
			    i++)
				RB_LEFT(&ne[i], daddrs.addr_entry) = &ne[i + 1];
			RB_LEFT(&ne[i], daddrs.addr_entry) = NULL;
			me = ne;
			if (ratecheck(&uvm_kmapent_last_warn_time,
			    &uvm_kmapent_warn_rate))
				printf("uvm_mapent_alloc: out of static "
				    "map entries\n");
		}
		uvm.kentry_free = RB_LEFT(me, daddrs.addr_entry);
		uvmexp.kmapent++;
		mtx_leave(&uvm_kmapent_mtx);
		me->flags = UVM_MAP_STATIC;
	} else if (map == kernel_map) {
		splassert(IPL_NONE);
		me = pool_get(&uvm_map_entry_kmem_pool, pool_flags);
		if (me == NULL)
			goto out;
		me->flags = UVM_MAP_KMEM;
	} else {
		splassert(IPL_NONE);
		me = pool_get(&uvm_map_entry_pool, pool_flags);
		if (me == NULL)
			goto out;
		me->flags = 0;
	}

	if (me != NULL) {
		RB_LEFT(me, daddrs.addr_entry) =
		    RB_RIGHT(me, daddrs.addr_entry) =
		    RB_PARENT(me, daddrs.addr_entry) = UVMMAP_DEADBEEF;
	}

out:
	return(me);
}
{% endhighlight %}

Finally, we're starting to get to the good stuff.  This calls `km_alloc`, which is [defined in `src/sys/uvm/uvm_km.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_km.c?rev=1.126.6.1&content-type=text/x-cvsweb-markup):

{% highlight C %}
void *
km_alloc(size_t sz, const struct kmem_va_mode *kv,
    const struct kmem_pa_mode *kp, const struct kmem_dyn_mode *kd)
{
	struct vm_map *map;
	struct vm_page *pg;
	struct pglist pgl;
	int mapflags = 0;
	vm_prot_t prot;
	paddr_t pla_align;
	int pla_flags;
	int pla_maxseg;
	vaddr_t va, sva;

	KASSERT(sz == round_page(sz));

	TAILQ_INIT(&pgl);

	if (kp->kp_nomem || kp->kp_pageable)
		goto alloc_va;

	pla_flags = kd->kd_waitok ? UVM_PLA_WAITOK : UVM_PLA_NOWAIT;
	pla_flags |= UVM_PLA_TRYCONTIG;
	if (kp->kp_zero)
		pla_flags |= UVM_PLA_ZERO;

	pla_align = kp->kp_align;
#ifdef __HAVE_PMAP_DIRECT
	if (pla_align < kv->kv_align)
		pla_align = kv->kv_align;
#endif
	pla_maxseg = kp->kp_maxseg;
	if (pla_maxseg == 0)
		pla_maxseg = sz / PAGE_SIZE;

	if (uvm_pglistalloc(sz, kp->kp_constraint->ucr_low,
	    kp->kp_constraint->ucr_high, pla_align, kp->kp_boundary,
	    &pgl, pla_maxseg, pla_flags)) {	
		return (NULL);
	}

#ifdef __HAVE_PMAP_DIRECT
	/*
	 * Only use direct mappings for single page or single segment
	 * allocations.
	 */
	if (kv->kv_singlepage || kp->kp_maxseg == 1) {
		TAILQ_FOREACH(pg, &pgl, pageq) {
			va = pmap_map_direct(pg);
			if (pg == TAILQ_FIRST(&pgl))
				sva = va;
		}
		return ((void *)sva);
	}
#endif
alloc_va:
	prot = PROT_READ | PROT_WRITE;

	if (kp->kp_pageable) {
		KASSERT(kp->kp_object);
		KASSERT(!kv->kv_singlepage);
	} else {
		KASSERT(kp->kp_object == NULL);
	}

	if (kv->kv_singlepage) {
		KASSERT(sz == PAGE_SIZE);
#ifdef __HAVE_PMAP_DIRECT
		panic("km_alloc: DIRECT single page");
#else
		mtx_enter(&uvm_km_pages.mtx);
		while (uvm_km_pages.free == 0) {
			if (kd->kd_waitok == 0) {
				mtx_leave(&uvm_km_pages.mtx);
				uvm_pglistfree(&pgl);
				return NULL;
			}
			msleep(&uvm_km_pages.free, &uvm_km_pages.mtx, PVM,
			    "getpage", 0);
		}
		va = uvm_km_pages.page[--uvm_km_pages.free];
		if (uvm_km_pages.free < uvm_km_pages.lowat &&
		    curproc != uvm_km_pages.km_proc) {
			if (kd->kd_slowdown)
				*kd->kd_slowdown = 1;
			wakeup(&uvm_km_pages.km_proc);
		}
		mtx_leave(&uvm_km_pages.mtx);
#endif
	} else {
		struct uvm_object *uobj = NULL;

		if (kd->kd_trylock)
			mapflags |= UVM_KMF_TRYLOCK;

		if (kp->kp_object)
			uobj = *kp->kp_object;
try_map:
		map = *kv->kv_map;
		va = vm_map_min(map);
		if (uvm_map(map, &va, sz, uobj, kd->kd_prefer,
		    kv->kv_align, UVM_MAPFLAG(prot, prot, MAP_INHERIT_NONE,
		    MADV_RANDOM, mapflags))) {
			if (kv->kv_wait && kd->kd_waitok) {
				tsleep(map, PVM, "km_allocva", 0);
				goto try_map;
			}
			uvm_pglistfree(&pgl);
			return (NULL);
		}
	}
	sva = va;
	TAILQ_FOREACH(pg, &pgl, pageq) {
		if (kp->kp_pageable)
			pmap_enter(pmap_kernel(), va, VM_PAGE_TO_PHYS(pg),
			    prot, prot | PMAP_WIRED);
		else
			pmap_kenter_pa(va, VM_PAGE_TO_PHYS(pg), prot);
		va += PAGE_SIZE;
	}
	pmap_update(pmap_kernel());
	return ((void *)sva);
}
{% endhighlight %}

Whew.  That's a lot to unravel, so I'll leave it here for now.

# References

For the section on FreeBSD, I referred to ["The Design and Implementation of FreeBSD."](http://www.amazon.com/Design-Implementation-FreeBSD-Operating-Edition/dp/0321968972)  For the section on NetBSD and OpenBSD, I referred to Charles Cranor's dissertation ["Design and Implementation of the UVM Virtual Memory System."](http://chuck.cranor.org/p/diss.pdf)

# Attribution

The diagram for UVM's data structures comes from [Charles Craynor's paper at Usenix in 1999](http://usenix.org/legacy/publications/library/proceedings/usenix99/full_papers/cranor/cranor_html/index.html), of which there is also [a PDF version](https://www.usenix.org/event/usenix99/full_papers/cranor/cranor.pdf).
