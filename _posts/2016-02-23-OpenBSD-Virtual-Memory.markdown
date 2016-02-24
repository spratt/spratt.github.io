---
published: true
title: OpenBSD Virtual Memory
layout: post
tags: [OS, bsd, openbsd, unix, virtual memory]
---

Today, we answer the following questions about OpenBSD's virtual memory system:

- How are contiguous regions of memory managed?
- How is memory freed?
    - What happens when the kernel runs out of memory?
- Is there any special code for Non-Uniform Memory Access (NUMA) architectures?
- How is physical memory managed?
    - Does it assume more virtual than physical memory?
- What are its data structures which store information about memory?

Along the way, I'll show the relevant parts of the OpenBSD source and link to their location in their web CVS, which should serve both as a map and let anyone interested easily find out more.  But first, we'll look at UVM's design at a high-level.

# UVM Design Overview

As we learned in [the article on BSD's virtual memory system](/2016/02/02/BSD-virtual-memory/), Charles Cranor wrote [his PhD dissertation](http://chuck.cranor.org/p/diss.pdf) on his massive rewrite of NetBSD's VM system, which he called UVM.  This rewrite was meant to address the following issues in 4.4BSD's VM, which was based on Mach's VM:

- shadow/copy object chaining
- one page at a time I/O operations
- poor integration with the kernel

When a process is [`fork`](http://pubs.opengroup.org/onlinepubs/9699919799/functions/fork.html)ed, its existing address space is copied to the new process.  Since actually copying the entire address space would be a tremendous overhead on every call to `fork`, and since a common pattern in unix is to immediately fork and kill the original process to start a process in the background, POSIX systems typically don't actually copy the address space.  In 4.4BSD, a `fork` creates a "copy" object between the `vm_map_entry` and the `vnode`.  This allows the kernel to fault on any writes to this memory, and only then copy the data to the writing process' address space.  This mechanism is called copy-on-write.   (See section 5.5, page 146 of The Design and Implementation of the 4.4BSD Operating System.)

Similarly, when a process has a private mapping from memory to a file, this means that changes made by that process are not reflected in the file but are visible to that process.  To support this, 4.4BSD creates a "shadow" object between the `vm_map_entry` and the file object, which stores the private changes made by the process to the file.  (See section 5.5, page 142 of The Design and Implementation of the 4.4BSD Operating System.)

These shadow/copy object chains can get quite long, which slows memory search times and can contain inaccessible redundant copies of the same page of data.  If left unchecked, this can fill swap space with redundant data and cause the system to deadlock, these are called swap memory leak deadlocks.  4.4BSD addresses this problem with a `collapse` operation which can bypass or discards any redundant pages that are still accessible, but this process can't do anything to redundant pages that have become inaccessible.

UVM simplifies the copy-on-write mechanisms by replacing shadow/copy objects with a 2-level scheme based on page reference counters.  UVM also uses these reference counters to eliminate swap memory leaks.

Second on the list of issues meant to be addressed by UVM is the fact that I/O operations in the BSD VM are performed one page at a time, which slows paging response time.  UVM addresses this by allowing such operations on multi-page clusters.

Finally, Cranor claims that BSD's VM is poorly integrated with the kernel, and gives the example that unreferenced memory-mapped file objects are cached both at the I/O system (`vnode`) layer, and redundantly at the VM layer as well.

## Locking

Section 3.3.2 of [Cranor's dissertation](http://chuck.cranor.org/p/diss.pdf) describes data structure locking, noting that OS data structures can be protected either by one big lock or by many small "fine-grained" locks.  It goes on to say that when Mach's VM system was ported to BSD, they ignored its fine-grained locking support.  One of UVM's goals is to restore this fine-grained locking support.

# Contiguous Memory Management

What data structure is used to represent a contiguous region of memory?  Well, the `uvm_object` struct is used to provide a reference to a backing store (such as physical memory), and can hold references to a contiguous sequence of pages.  But there's no mechanism to allocate contiguous regions of physical memory aside from the direct-memory-access (DMA) interface meant for driver developers.

# Freeing Memory

What actually happens when we call `munmap()`?  Well, rather than go through *yet another* trail of indirection citing the code at every step, I'll simply look through the code and enumerate the calls here:

1. `sys_munmap()` system call in [`src/sys/uvm/uvm_mmap.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_mmap.c?rev=1.122&content-type=text/x-cvsweb-markup) calls `uvm_unmap_remove(map, addr, addr + size, &dead_entries, FALSE, TRUE)`
2. `uvm_unmap_remove(struct vm_map *map, vaddr_t start, vaddr_t end,
    struct uvm_map_deadq *dead, boolean_t remove_holes,
    boolean_t markfree)` in [`src/sys/uvm/uvm_map.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_map.c?rev=1.205&content-type=text/x-cvsweb-markup) calls `uvm_mapent_mkfree(map, entry, &prev_hint, dead, markfree)`
3. `uvm_mapent_mkfree(struct vm_map *map, struct vm_map_entry *entry,
    struct vm_map_entry **prev_ptr, struct uvm_map_deadq *dead,
    boolean_t markfree)` in [the same file](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_map.c?rev=1.205&content-type=text/x-cvsweb-markup), which mostly just seems to put the entry into a queue of dead entries.

## What happens when the kernel runs out of memory?

When a user process runs out of memory, a call to `mmap` simply returns the `ENOMEM` error, as we can see in [`src/sys/uvm/uvm_mmap.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_mmap.c?rev=1.122&content-type=text/x-cvsweb-markup):

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
	/* check for file mappings (i.e. not anonymous) and verify file. */
	if ((flags & MAP_ANON) == 0) {
	/* ... */
	} else {		/* MAP_ANON case */
		if ((flags & MAP_ANON) != 0 ||
		    ((flags & MAP_PRIVATE) != 0 && (prot & PROT_WRITE) != 0)) {
			if (size >
			    (p->p_rlimit[RLIMIT_DATA].rlim_cur - ptoa(p->p_vmspace->vm_dused))) {
				return ENOMEM;
			}
		}
	/* ... */
	}
	/* ... */
}
{% endhighlight %}

But when the kernel runs out of memory, we see a `panic` as in [`src/sys/uvm/uvm_map.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_map.c?rev=1.205&content-type=text/x-cvsweb-markup):

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
			/* ... */
		}
		/* ... */
	}
	/* ... */
}
{% endhighlight %}

# NUMA

[Non-Uniform Memory Access (NUMA)](https://en.wikipedia.org/wiki/Non-uniform_memory_access) is when each processor has some section of fast memory which is considered "local," and the rest is much slower and considered "remote."  Section 5.2.16 of [the ACPI specification](http://www.acpi.info/spec.htm) defines the System Resource Affinity Table (SRAT) which associates processors and memory to proximity domains, essentially what memory is local to which processor.  Section 5.2.17 of the same spec defines the System Locality Distance Information Table (SLIT) which provides information about the memory latency for each proximity domain.

I learned on [hubertf's blog](http://www.feyrer.de/NetBSD/bx/blosxom.cgi/index.front?-tags=numa) that Christoph Egger wrote [an ACPI SLIT parser](http://mail-index.netbsd.org/tech-kern/2009/11/23/msg006518.html) and [an ACPI SRAT parser](http://mail-index.netbsd.org/tech-kern/2009/11/23/msg006517.html) for NetBSD.  Indeed, [the `src/sys/dev/acpi` directory in NetBSD's CVS](http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/dev/acpi/?only_with_tag=MAIN) contains [`acpi_slit.h`](http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/dev/acpi/acpi_slit.h?rev=1.3&content-type=text/x-cvsweb-markup&only_with_tag=MAIN), [`acpi_slit.c`](http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/dev/acpi/acpi_slit.c?rev=1.3&content-type=text/x-cvsweb-markup&only_with_tag=MAIN), [`acpi_srat.h`](http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/dev/acpi/acpi_srat.h?rev=1.3&content-type=text/x-cvsweb-markup&only_with_tag=MAIN), and [`acpi_srat.c`](http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/dev/acpi/acpi_srat.c?rev=1.3&content-type=text/x-cvsweb-markup&only_with_tag=MAIN).  No similar files exist in OpenBSD, which suggests that they haven't been ported.

[There seems to have been some work done on adding NUMA support as well as the concept of memory and CPU affinity to OpenBSD](http://openbsd-archive.7691.n7.nabble.com/numa-implementation-td165563.html), but nothing since 2009.  [A search within OpenBSD's web CVS reveals no mention of numa](http://www.google.com/#q=numa%20site:http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/), which suggests that Ariane's patch was never accepted.

## What about other BSDs?

[The paper describing DragonFly BSD's design goals as a fork of FreeBSD states that it is designed with a NUMA-centric view](http://www.dragonflybsd.org/presentations/dragonflybsd.asiabsdcon04.pdf), by explicitly partitioning the workload among multiple processors.  [There was also a Google Summer of Code project in 2010 to make DragonFly BSD NUMA-aware](https://www.dragonflybsd.org/mailarchive/kernel/2010-03/msg00119.html).

# Physical Memory Management

The BSD VM system is split into two layers: machine dependent and independent.  UVM's machine-dependent layer is essentially the same as BSD's, which is called the `pmap` layer.  `pmap` handles adding to, removing from, or querying for virtual or physical mappings within the processor's memory management unit (MMU).

The `pmap` layer is a deliberately thin abstraction over the MMU, in order that the VM code built on top can reuse as much code as possible across every supported platform.  This also lets us hide shortcomings of the MMU, such as painfully small page sizes on the VAX, by dealing with such things at the `pmap` layer.  Unfortunately, it has a symmetric shortcoming of its own, in that it abstracts away the nicer features of any MMU in order to provide a simple interface supported by all architectures.  Also, this means that memory information is stored both in the page tables manipulated by the `pmap` layer, and in the higher-level UVM structures.

The `pmap` structure is in [`src/sys/arch/i386/include/pmap.h`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/arch/i386/include/pmap.h?rev=1.79&content-type=text/x-cvsweb-markup):

{% highlight C %}
/*
 * The pmap structure
 *
 * Note that the pm_obj contains the reference count,
 * page list, and number of PTPs within the pmap.
 */

struct pmap {
	uint64_t pm_pdidx[4];		/* PDIEs for PAE mode */

	struct mutex pm_mtx;
	struct mutex pm_apte_mtx;

	paddr_t pm_pdirpa;		/* PA of PD (read-only after create) */
	vaddr_t pm_pdir;		/* VA of PD (lck by object lock) */
	int	pm_pdirsize;		/* PD size (4k vs 16k on PAE) */
	struct uvm_object pm_obj;	/* object (lck by object lock) */
	LIST_ENTRY(pmap) pm_list;	/* list (lck by pm_list lock) */
	struct vm_page *pm_ptphint;	/* pointer to a PTP in our pmap */
	struct pmap_statistics pm_stats;  /* pmap stats (lck by object lock) */

	vaddr_t pm_hiexec;		/* highest executable mapping */
	int pm_flags;			/* see below */

	struct segment_descriptor pm_codeseg;	/* cs descriptor for process */
	union descriptor *pm_ldt;	/* user-set LDT */
	int pm_ldt_len;			/* number of LDT entries */
	int pm_ldt_sel;			/* LDT selector */
};
{% endhighlight %}

## Do they assume more virtual than physical addresses?

Although this used to be a reasonable assumption on x86, the x86-64 specification has a bigger physical address space (52 bits) than virtual address space (48 bits).

On Linux, the kernel allocates every page of physical memory into the kernel's virtual address space.  This makes the fundamental assumption that there will always be more virtual than physical memory.

I can't find any definitive proof, but I will show how UVM initializes memory.  First, let's see how the kernel is initialized in [`src/sys/kern/init_main.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/init_main.c?rev=1.248&content-type=text/x-cvsweb-markup):

{% highlight C %}
/*
 * System startup; initialize the world, create process 0, mount root
 * filesystem, and fork to create init and pagedaemon.  Most of the
 * hard work is done in the lower-level initialization routines including
 * startup(), which does memory initialization and autoconfiguration.
 */
/* XXX return int, so gcc -Werror won't complain */
int
main(void *framep)
{
	struct proc *p;
	struct process *pr;
	struct pdevinit *pdev;
	quad_t lim;
	int s, i;
	extern struct pdevinit pdevinit[];
	extern void disk_init(void);

	/*
	 * Initialize the current process pointer (curproc) before
	 * any possible traps/probes to simplify trap processing.
	 */
	curproc = p = &proc0;
	p->p_cpu = curcpu();

	/*
	 * Initialize timeouts.
	 */
	timeout_startup();

	/*
	 * Attempt to find console and initialize
	 * in case of early panic or other messages.
	 */
	config_init();		/* init autoconfiguration data structures */
	consinit();

	printf("%s\n", copyright);

	KERNEL_LOCK_INIT();
	SCHED_LOCK_INIT();

	uvm_init();
	/* ... */
}
{% endhighlight %}

And we can find the code for `uvm_init` in [`src/sys/uvm/uvm_init.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_init.c?rev=1.39&content-type=text/x-cvsweb-markup):

{% highlight C %}
/*
 * uvm_init: init the VM system.   called from kern/init_main.c.
 */
void
uvm_init(void)
{
	vaddr_t kvm_start, kvm_end;

	/* step 0: ensure that the hardware set the page size */
	if (uvmexp.pagesize == 0) {
		panic("uvm_init: page size not set");
	}

	/* step 1: set up stats. */
	averunnable.fscale = FSCALE;

	/*
	 * step 2: init the page sub-system.  this includes allocating the
	 * vm_page structures, and setting up all the page queues (and
	 * locks).  available memory will be put in the "free" queue.
	 * kvm_start and kvm_end will be set to the area of kernel virtual
	 * memory which is available for general use.
	 */
	uvm_page_init(&kvm_start, &kvm_end);

	/*
	 * step 3: init the map sub-system.  allocates the static pool of
	 * vm_map_entry structures that are used for "special" kernel maps
	 * (e.g. kernel_map, kmem_map, etc...).
	 */
	uvm_map_init();

	/*
	 * step 4: setup the kernel's virtual memory data structures.  this
	 * includes setting up the kernel_map/kernel_object and the kmem_map/
	 * kmem_object.
	 */

	uvm_km_init(vm_min_kernel_address, kvm_start, kvm_end);

	/*
	 * step 4.5: init (tune) the fault recovery code.
	 */
	uvmfault_init();

	/*
	 * step 5: init the pmap module.   the pmap module is free to allocate
	 * memory for its private use (e.g. pvlists).
	 */
	pmap_init();

	/*
	 * step 6: init the kernel memory allocator.   after this call the
	 * kernel memory allocator (malloc) can be used.
	 */
	kmeminit();

	/*
	 * step 6.5: init the dma allocator, which is backed by pools.
	 */
	dma_alloc_init();

	/*
	 * step 7: init all pagers and the pager_map.
	 */
	uvm_pager_init();

	/*
	 * step 8: init anonymous memory system
	 */
	amap_init();

	/*
	 * step 9: init uvm_km_page allocator memory.
	 */
	uvm_km_page_init();

	/*
	 * the VM system is now up!  now that malloc is up we can
	 * enable paging of kernel objects.
	 */
	uao_create(VM_KERNEL_SPACE_SIZE, UAO_FLAG_KERNSWAP);

	/*
	 * reserve some unmapped space for malloc/pool use after free usage
	 */
#ifdef DEADBEEF0
	kvm_start = trunc_page(DEADBEEF0) - PAGE_SIZE;
	if (uvm_map(kernel_map, &kvm_start, 3 * PAGE_SIZE,
	    NULL, UVM_UNKNOWN_OFFSET, 0, UVM_MAPFLAG(PROT_NONE,
	    PROT_NONE, MAP_INHERIT_NONE, MADV_RANDOM, UVM_FLAG_FIXED)))
		panic("uvm_init: cannot reserve dead beef @0x%x", DEADBEEF0);
#endif
#ifdef DEADBEEF1
	kvm_start = trunc_page(DEADBEEF1) - PAGE_SIZE;
	if (uvm_map(kernel_map, &kvm_start, 3 * PAGE_SIZE,
	    NULL, UVM_UNKNOWN_OFFSET, 0, UVM_MAPFLAG(PROT_NONE,
	    PROT_NONE, MAP_INHERIT_NONE, MADV_RANDOM, UVM_FLAG_FIXED)))
		panic("uvm_init: cannot reserve dead beef @0x%x", DEADBEEF1);
#endif
	/*
	 * init anonymous memory systems
	 */
	uvm_anon_init();

#ifndef SMALL_KERNEL
	/*
	 * Switch kernel and kmem_map over to a best-fit allocator,
	 * instead of walking the tree.
	 */
	uvm_map_set_uaddr(kernel_map, &kernel_map->uaddr_any[3],
	    uaddr_bestfit_create(vm_map_min(kernel_map),
	    vm_map_max(kernel_map)));
	uvm_map_set_uaddr(kmem_map, &kmem_map->uaddr_any[3],
	    uaddr_bestfit_create(vm_map_min(kmem_map),
	    vm_map_max(kmem_map)));
#endif /* !SMALL_KERNEL */
}
{% endhighlight %}

As far as I can tell, none of these `_init()` functions does anything like map all of physical memory into the kernel's virtual address space.

# Data Structures

For the upper level, we have the following from Cranor's Usenix paper about UVM:

<img src="http://www.pr4tt.com/wiki/lib/exe/fetch.php?media=uvm.gif" style="width:100%" />

We'll just go through and look at each of the struct definitions for now.

The `vmspace` struct is defined in [`src/sys/uvm/uvm_extern.h`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_extern.h?rev=1.137&content-type=text/x-cvsweb-markup):

{% highlight C %}
/*
 * Shareable process virtual address space.
 * May eventually be merged with vm_map.
 * Several fields are temporary (text, data stuff).
 */
struct vmspace {
	struct	vm_map vm_map;	/* VM address map */
	int	vm_refcnt;	/* number of references */
	caddr_t	vm_shm;		/* SYS5 shared memory private data XXX */
/* we copy from vm_startcopy to the end of the structure on fork */
#define vm_startcopy vm_rssize
	segsz_t vm_rssize; 	/* current resident set size in pages */
	segsz_t vm_swrss;	/* resident set size before last swap */
	segsz_t vm_tsize;	/* text size (pages) XXX */
	segsz_t vm_dsize;	/* data size (pages) XXX */
	segsz_t vm_dused;	/* data segment length (pages) XXX */
	segsz_t vm_ssize;	/* stack size (pages) */
	caddr_t	vm_taddr;	/* user virtual address of text XXX */
	caddr_t	vm_daddr;	/* user virtual address of data XXX */
	caddr_t vm_maxsaddr;	/* user VA at max stack growth */
	caddr_t vm_minsaddr;	/* user VA at top of stack */
};
{% endhighlight %}

The `vm_map` struct is defined in [`src/sys/uvm/uvm_map.h`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_map.h?rev=1.55&content-type=text/x-cvsweb-markup):

{% highlight C %}
/*
 *	A Map is a rbtree of map entries, kept sorted by address.
 *	In addition, free space entries are also kept in a rbtree,
 *	indexed by free size.
 *
 *
 *
 *	LOCKING PROTOCOL NOTES:
 *	-----------------------
 *
 *	VM map locking is a little complicated.  There are both shared
 *	and exclusive locks on maps.  However, it is sometimes required
 *	to downgrade an exclusive lock to a shared lock, and upgrade to
 *	an exclusive lock again (to perform error recovery).  However,
 *	another thread *must not* queue itself to receive an exclusive
 *	lock while before we upgrade back to exclusive, otherwise the
 *	error recovery becomes extremely difficult, if not impossible.
 *
 *	In order to prevent this scenario, we introduce the notion of
 *	a `busy' map.  A `busy' map is read-locked, but other threads
 *	attempting to write-lock wait for this flag to clear before
 *	entering the lock manager.  A map may only be marked busy
 *	when the map is write-locked (and then the map must be downgraded
 *	to read-locked), and may only be marked unbusy by the thread
 *	which marked it busy (holding *either* a read-lock or a
 *	write-lock, the latter being gained by an upgrade).
 *
 *	Access to the map `flags' member is controlled by the `flags_lock'
 *	simple lock.  Note that some flags are static (set once at map
 *	creation time, and never changed), and thus require no locking
 *	to check those flags.  All flags which are r/w must be set or
 *	cleared while the `flags_lock' is asserted.  Additional locking
 *	requirements are:
 *
 *		VM_MAP_PAGEABLE		r/o static flag; no locking required
 *
 *		VM_MAP_INTRSAFE		r/o static flag; no locking required
 *
 *		VM_MAP_WIREFUTURE	r/w; may only be set or cleared when
 *					map is write-locked.  may be tested
 *					without asserting `flags_lock'.
 *
 *		VM_MAP_BUSY		r/w; may only be set when map is
 *					write-locked, may only be cleared by
 *					thread which set it, map read-locked
 *					or write-locked.  must be tested
 *					while `flags_lock' is asserted.
 *
 *		VM_MAP_WANTLOCK		r/w; may only be set when the map
 *					is busy, and thread is attempting
 *					to write-lock.  must be tested
 *					while `flags_lock' is asserted.
 *
 *		VM_MAP_GUARDPAGES	r/o; must be specified at map
 *					initialization time.
 *					If set, guards will appear between
 *					automatic allocations.
 *					No locking required.
 *
 *		VM_MAP_ISVMSPACE	r/o; set by uvmspace_alloc.
 *					Signifies that this map is a vmspace.
 *					(The implementation treats all maps
 *					without this bit as kernel maps.)
 *					No locking required.
 *
 *
 * All automatic allocations (uvm_map without MAP_FIXED) will allocate
 * from vm_map.free.
 * If that allocation fails:
 * - vmspace maps will spill over into vm_map.bfree,
 * - all other maps will call uvm_map_kmem_grow() to increase the arena.
 * 
 * vmspace maps have their data, brk() and stack arenas automatically
 * updated when uvm_map() is invoked without MAP_FIXED.
 * The spill over arena (vm_map.bfree) will contain the space in the brk()
 * and stack ranges.
 * Kernel maps never have a bfree arena and this tree will always be empty.
 *
 *
 * read_locks and write_locks are used in lock debugging code.
 */
struct vm_map {
	struct pmap *		pmap;		/* Physical map */
	struct rwlock		lock;		/* Lock for map data */
	struct mutex		mtx;

	struct uvm_map_addr	addr;		/* Entry tree, by addr */

	vsize_t			size;		/* virtual size */
	int			ref_count;	/* Reference count */
	int			flags;		/* flags */
	struct mutex		flags_lock;	/* flags lock */
	unsigned int		timestamp;	/* Version number */

	vaddr_t			min_offset;	/* First address in map. */
	vaddr_t			max_offset;	/* Last address in map. */

	/*
	 * Allocation overflow regions.
	 */
	vaddr_t			b_start;	/* Start for brk() alloc. */
	vaddr_t			b_end;		/* End for brk() alloc. */
	vaddr_t			s_start;	/* Start for stack alloc. */
	vaddr_t			s_end;		/* End for stack alloc. */

	/*
	 * Special address selectors.
	 *
	 * The uaddr_exe mapping is used if:
	 * - protX is selected
	 * - the pointer is not NULL
	 *
	 * If uaddr_exe is not used, the other mappings are checked in
	 * order of appearance.
	 * If a hint is given, the selection will only be used if the hint
	 * falls in the range described by the mapping.
	 *
	 * The states are pointers because:
	 * - they may not all be in use
	 * - the struct size for different schemes is variable
	 *
	 * The uaddr_brk_stack selector will select addresses that are in
	 * the brk/stack area of the map.
	 */
	struct uvm_addr_state	*uaddr_exe;	/* Executable selector. */
	struct uvm_addr_state	*uaddr_any[4];	/* More selectors. */
	struct uvm_addr_state	*uaddr_brk_stack; /* Brk/stack selector. */
};
{% endhighlight %}

The reference to `uvm_map_addr` is actually a reference to a red-black tree defined earlier:

{% highlight C %}
RB_HEAD(uvm_map_addr, vm_map_entry);
{% endhighlight %}

The `RB_HEAD` call is a standard part of NetBSD/OpenBSD, and we can look at [the relevant man page](http://netbsd.gw.com/cgi-bin/man-cgi?RB_HEAD+3+NetBSD-6.0):

{% highlight text %}
RED-BLACK TREES
     A red-black tree is a binary search tree with the node color as an extra
     attribute.  It fulfills a set of conditions:
           1.   every search path from the root to a leaf consists of the same
                number of black nodes,
           2.   each red node (except for the root) has a black parent,
           3.   each leaf node is black.

     Every operation on a red-black tree is bounded as O(lg n).  The maximum
     height of a red-black tree is 2lg (n+1).

     A red-black tree is headed by a structure defined by the RB_HEAD() macro.
     A RB_HEAD structure is declared as follows:

           RB_HEAD(HEADNAME, TYPE) head;

     where HEADNAME is the name of the structure to be defined, and struct
     TYPE is the type of the elements to be inserted into the tree.
{% endhighlight %}

So the type of elements stored in the `uvm_map_addr` red-black tree is `vm_map_entry` which is defined earlier in the same file as `vm_map`:

{% highlight C %}
/*
 * Address map entries consist of start and end addresses,
 * a VM object (or sharing map) and offset into that object,
 * and user-exported inheritance and protection information.
 * Also included is control information for virtual copy operations.
 */
struct vm_map_entry {
	union {
		RB_ENTRY(vm_map_entry)	addr_entry; /* address tree */
	} daddrs;

	union {
		RB_ENTRY(vm_map_entry)	rbtree;	/* Link freespace tree. */
		TAILQ_ENTRY(vm_map_entry) tailq;/* Link freespace queue. */
		TAILQ_ENTRY(vm_map_entry) deadq;/* dead entry queue */
	} dfree;

#define uvm_map_entry_start_copy start
	vaddr_t			start;		/* start address */
	vaddr_t			end;		/* end address */

	vsize_t			guard;		/* bytes in guard */
	vsize_t			fspace;		/* free space */

	union vm_map_object	object;		/* object I point to */
	voff_t			offset;		/* offset into object */
	struct vm_aref		aref;		/* anonymous overlay */

	int			etype;		/* entry type */

	vm_prot_t		protection;	/* protection code */
	vm_prot_t		max_protection;	/* maximum protection */
	vm_inherit_t		inheritance;	/* inheritance */

	int			wired_count;	/* can be paged if == 0 */
	int			advice;		/* madvise advice */
#define uvm_map_entry_stop_copy flags
	u_int8_t		flags;		/* flags */

#define UVM_MAP_STATIC		0x01		/* static map entry */
#define UVM_MAP_KMEM		0x02		/* from kmem entry pool */

	vsize_t			fspace_augment;	/* max(fspace) in subtree */
};
{% endhighlight %}

Notice also that a `vm_map_entry` has makes a couple of `TAILQ_ENTRY` calls, which create [another standard data structure](http://nixdoc.net/man-pages/openbsd/man3/TAILQ_HEAD.3.html), this time a tail queue:

{% highlight text %}
...
     TAILQ_ENTRY(TYPE);

     TAILQ_HEAD(HEADNAME, TYPE);
...
DESCRIPTION    [Toc]    [Back]

     These macros define and operate on five types of data structures: singlylinked
  lists, simple queues, lists, tail queues, and circular queues.
     All five structures support the following functionality:

           1.   Insertion of a new entry at the head of the list.
           2.   Insertion of a new entry after any element in the
list.
           3.   Removal of an entry from the head of the list.
           4.   Forward traversal through the list.
...
     Tail queues add the following functionality:

           1.   Entries can be added at the end of a list.
           2.   They may be traversed backwards, at a cost.

     However:

           1.   All list insertions and removals must specify the
head of the
                list.
           2.   Each head entry requires two pointers rather than
one.
           3.   Code size is about 15% greater and operations run
about 20%
                slower than singly-linked lists.
{% endhighlight %}

Exactly what the "dead" entry queue does, I'm not sure.  If we look at [the same struct in NetBSD](http://ftp.netbsd.org/pub/NetBSD/NetBSD-current/src/sys/uvm/uvm_map.h):

{% highlight C %}
/*
 * Address map entries consist of start and end addresses,
 * a VM object (or sharing map) and offset into that object,
 * and user-exported inheritance and protection information.
 * Also included is control information for virtual copy operations.
 */
struct vm_map_entry {
	struct rb_node		rb_node;	/* tree information */
	vsize_t			gap;		/* free space after */
	vsize_t			maxgap;		/* space in subtree */
	struct vm_map_entry	*prev;		/* previous entry */
	struct vm_map_entry	*next;		/* next entry */
	vaddr_t			start;		/* start address */
	vaddr_t			end;		/* end address */
	union {
		struct uvm_object *uvm_obj;	/* uvm object */
		struct vm_map	*sub_map;	/* belongs to another map */
	} object;				/* object I point to */
	voff_t			offset;		/* offset into object */
	int			etype;		/* entry type */
	vm_prot_t		protection;	/* protection code */
	vm_prot_t		max_protection;	/* maximum protection */
	vm_inherit_t		inheritance;	/* inheritance */
	int			wired_count;	/* can be paged if == 0 */
	struct vm_aref		aref;		/* anonymous overlay */
	int			advice;		/* madvise advice */
	uint32_t		map_attrib;	/* uvm-external map attributes */
#define uvm_map_entry_stop_copy flags
	u_int8_t		flags;		/* flags */

#define	UVM_MAP_KERNEL		0x01		/* kernel map entry */
#define	UVM_MAP_STATIC		0x04		/* special static entries */
#define	UVM_MAP_NOMERGE		0x08		/* this entry is not mergable */

};
{% endhighlight %}

We can see that it doesn't have a dead entry queue at all.  :/

The `vm_map_object` union is defined earlier in the same file:

{% highlight C %}
/*
 * Objects which live in maps may be either VM objects, or another map
 * (called a "sharing map") which denotes read-write sharing with other maps.
 *
 * XXXCDC: private pager data goes here now
 */

union vm_map_object {
	struct uvm_object	*uvm_obj;	/* UVM OBJECT */
	struct vm_map		*sub_map;	/* belongs to another map */
};
{% endhighlight %}

The `uvm_object` struct is defined in [`src/sys/uvm/uvm_object.h`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_object.h?rev=1.21&content-type=text/x-cvsweb-markup)

{% highlight C %}
/*
 * uvm_object: all that is left of mach objects.
 */

struct uvm_object {
	struct uvm_pagerops		*pgops;		/* pager ops */
	RB_HEAD(uvm_objtree, vm_page)	 memt;		/* pages in object */
	int				 uo_npages;	/* # of pages in memt */
	int				 uo_refs;	/* reference count */
};
{% endhighlight %}

From the definition of `uvm_object` we can see that it also contains a red-black tree of `vm_page` objects, which are defined in [`src/sys/uvm/uvm_page.h`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_page.h?rev=1.60&content-type=text/x-cvsweb-markup):

{% highlight C %}
/*
 *	Management of resident (logical) pages.
 *
 *	A small structure is kept for each resident
 *	page, indexed by page number.  Each structure
 *	contains a list used for manipulating pages, and
 *	a tree structure for in object/offset lookups
 *
 *	In addition, the structure contains the object
 *	and offset to which this page belongs (for pageout),
 *	and sundry status bits.
 *
 *	Fields in this structure are possibly locked by the lock on the page
 *	queues (P).
 */

TAILQ_HEAD(pglist, vm_page);

struct vm_page {
	TAILQ_ENTRY(vm_page)	pageq;		/* queue info for FIFO
						 * queue or free list (P) */
	RB_ENTRY(vm_page)	objt;		/* object tree */

	struct vm_anon		*uanon;		/* anon (P) */
	struct uvm_object	*uobject;	/* object (P) */
	voff_t			offset;		/* offset into object (P) */

	u_int			pg_flags;	/* object flags [P] */

	u_int			pg_version;	/* version count */
	u_int			wire_count;	/* wired down map refs [P] */

	paddr_t			phys_addr;	/* physical address of page */
	psize_t			fpgsz;		/* free page range size */

	struct vm_page_md	mdpage;		/* pmap-specific data */

#if defined(UVM_PAGE_TRKOWN)
	/* debugging fields to track page ownership */
	pid_t			owner;		/* proc that set PG_BUSY */
	char			*owner_tag;	/* why it was set busy */
#endif
};
{% endhighlight %}

The lowest level in the above diagram shows a "pager" object, which corresponds to the `uvm_pagerops` struct, which is defined in [`src/sys/uvm/uvm_pager.h`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_pager.h?rev=1.29&content-type=text/x-cvsweb-markup):

{% highlight C %}
struct uvm_pagerops {
						/* init pager */
	void			(*pgo_init)(void);
						/* add reference to obj */
	void			(*pgo_reference)(struct uvm_object *);
						/* drop reference to obj */
	void			(*pgo_detach)(struct uvm_object *);
						/* special nonstd fault fn */
	int			(*pgo_fault)(struct uvm_faultinfo *, vaddr_t,
				 vm_page_t *, int, int, vm_fault_t,
				 vm_prot_t, int);
						/* flush pages out of obj */
	boolean_t		(*pgo_flush)(struct uvm_object *, voff_t,
				 voff_t, int);
						/* get/read page */
	int			(*pgo_get)(struct uvm_object *, voff_t,
				 vm_page_t *, int *, int, vm_prot_t, int, int);
						/* put/write page */
	int			(*pgo_put)(struct uvm_object *, vm_page_t *,
				 int, boolean_t);
						/* return range of cluster */
	void			(*pgo_cluster)(struct uvm_object *, voff_t,
				 voff_t *, voff_t *);
						/* make "put" cluster */
	struct vm_page **	(*pgo_mk_pcluster)(struct uvm_object *,
				 struct vm_page **, int *, struct vm_page *,
				 int, voff_t, voff_t);
};
{% endhighlight %}

As we can see, this effectively implements a kind of multiple dispatch in which the underlying "pager" implements these functions and stores pointers to them in a `uvm_pagerops` struct.

# Conclusion

TODO

# Aside: x86 MMU<a name="x86-mmu">&nbsp;</a>

The x86 implementation of pmap, located in [`src/sys/arch/i386/i386/pmap.c`](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/arch/i386/i386/pmap.c?rev=1.186&content-type=text/x-cvsweb-markup) contains some nice documentation for the x86 MMU:

{% highlight C %}
/*
 * this file contains the code for the "pmap module."   the module's
 * job is to manage the hardware's virtual to physical address mappings.
 * note that there are two levels of mapping in the VM system:
 *
 *  [1] the upper layer of the VM system uses vm_map's and vm_map_entry's
 *      to map ranges of virtual address space to objects/files.  for
 *      example, the vm_map may say: "map VA 0x1000 to 0x22000 read-only
 *      to the file /bin/ls starting at offset zero."   note that
 *      the upper layer mapping is not concerned with how individual
 *      vm_pages are mapped.
 *
 *  [2] the lower layer of the VM system (the pmap) maintains the mappings
 *      from virtual addresses.   it is concerned with which vm_page is
 *      mapped where.   for example, when you run /bin/ls and start
 *      at page 0x1000 the fault routine may lookup the correct page
 *      of the /bin/ls file and then ask the pmap layer to establish
 *      a mapping for it.
 *
 * note that information in the lower layer of the VM system can be
 * thrown away since it can easily be reconstructed from the info
 * in the upper layer.
 *
 * data structures we use include:
 *
 *  - struct pmap: describes the address space of one thread
 *  - struct pv_entry: describes one <PMAP,VA> mapping of a PA
 *  - struct pv_head: there is one pv_head per managed page of
 *	physical memory.   the pv_head points to a list of pv_entry
 *	structures which describe all the <PMAP,VA> pairs that this
 *      page is mapped in.    this is critical for page based operations
 *      such as pmap_page_protect() [change protection on _all_ mappings
 *      of a page]
 */
/*
 * i386 MMU hardware structure:
 *
 * the i386 MMU is a two-level MMU which maps 4GB of virtual memory.
 * the pagesize is 4K (4096 [0x1000] bytes), although newer pentium
 * processors can support a 4MB pagesize as well.
 *
 * the first level table (segment table?) is called a "page directory"
 * and it contains 1024 page directory entries (PDEs).   each PDE is
 * 4 bytes (an int), so a PD fits in a single 4K page.   this page is
 * the page directory page (PDP).  each PDE in a PDP maps 4MB of space
 * (1024 * 4MB = 4GB).   a PDE contains the physical address of the
 * second level table: the page table.   or, if 4MB pages are being used,
 * then the PDE contains the PA of the 4MB page being mapped.
 *
 * a page table consists of 1024 page table entries (PTEs).  each PTE is
 * 4 bytes (an int), so a page table also fits in a single 4K page.  a
 * 4K page being used as a page table is called a page table page (PTP).
 * each PTE in a PTP maps one 4K page (1024 * 4K = 4MB).   a PTE contains
 * the physical address of the page it maps and some flag bits (described
 * below).
 *
 * the processor has a special register, "cr3", which points to the
 * the PDP which is currently controlling the mappings of the virtual
 * address space.
 *
 * the following picture shows the translation process for a 4K page:
 *
 * %cr3 register [PA of PDP]
 *      |
 *      |
 *      |   bits <31-22> of VA         bits <21-12> of VA   bits <11-0>
 *      |   index the PDP (0 - 1023)   index the PTP        are the page offset
 *      |         |                           |                  |
 *      |         v                           |                  |
 *      +--->+----------+                     |                  |
 *           | PD Page  |   PA of             v                  |
 *           |          |---PTP-------->+------------+           |
 *           | 1024 PDE |               | page table |--PTE--+   |
 *           | entries  |               | (aka PTP)  |       |   |
 *           +----------+               | 1024 PTE   |       |   |
 *                                      | entries    |       |   |
 *                                      +------------+       |   |
 *                                                           |   |
 *                                                bits <31-12>   bits <11-0>
 *                                                p h y s i c a l  a d d r
 *
 * the i386 caches PTEs in a TLB.   it is important to flush out old
 * TLB mappings when making a change to a mapping.   writing to the
 * %cr3 will flush the entire TLB.    newer processors also have an
 * instruction that will invalidate the mapping of a single page (which
 * is useful if you are changing a single mapping because it preserves
 * all the cached TLB entries).
 *
 * as shows, bits 31-12 of the PTE contain PA of the page being mapped.
 * the rest of the PTE is defined as follows:
 *   bit#	name	use
 *   11		n/a	available for OS use, hardware ignores it
 *   10		n/a	available for OS use, hardware ignores it
 *   9		n/a	available for OS use, hardware ignores it
 *   8		G	global bit (see discussion below)
 *   7		PS	page size [for PDEs] (0=4k, 1=4M <if supported>)
 *   6		D	dirty (modified) page
 *   5		A	accessed (referenced) page
 *   4		PCD	cache disable
 *   3		PWT	prevent write through (cache)
 *   2		U/S	user/supervisor bit (0=supervisor only, 1=both u&s)
 *   1		R/W	read/write bit (0=read only, 1=read-write)
 *   0		P	present (valid)
 *
 * notes:
 *  - on the i386 the R/W bit is ignored if processor is in supervisor
 *    state (bug!)
 *  - PS is only supported on newer processors
 *  - PTEs with the G bit are global in the sense that they are not
 *    flushed from the TLB when %cr3 is written (to flush, use the
 *    "flush single page" instruction).   this is only supported on
 *    newer processors.    this bit can be used to keep the kernel's
 *    TLB entries around while context switching.   since the kernel
 *    is mapped into all processes at the same place it does not make
 *    sense to flush these entries when switching from one process'
 *    pmap to another.
 */
/*
 * A pmap describes a process' 4GB virtual address space.  This
 * virtual address space can be broken up into 1024 4MB regions which
 * are described by PDEs in the PDP.  The PDEs are defined as follows:
 *
 * Ranges are inclusive -> exclusive, just like vm_map_entry start/end.
 * The following assumes that KERNBASE is 0xd0000000.
 *
 * PDE#s	VA range		Usage
 * 0->831	0x0 -> 0xcfc00000	user address space, note that the
 *					max user address is 0xcfbfe000
 *					the final two pages in the last 4MB
 *					used to be reserved for the UAREA
 *					but now are no longer used.
 * 831		0xcfc00000->		recursive mapping of PDP (used for
 *			0xd0000000	linear mapping of PTPs).
 * 832->1023	0xd0000000->		kernel address space (constant
 *			0xffc00000	across all pmaps/processes).
 * 1023		0xffc00000->		"alternate" recursive PDP mapping
 *			<end>		(for other pmaps).
 *
 *
 * Note: A recursive PDP mapping provides a way to map all the PTEs for
 * a 4GB address space into a linear chunk of virtual memory.  In other
 * words, the PTE for page 0 is the first int mapped into the 4MB recursive
 * area.  The PTE for page 1 is the second int.  The very last int in the
 * 4MB range is the PTE that maps VA 0xffffe000 (the last page in a 4GB
 * address).
 *
 * All pmaps' PDs must have the same values in slots 832->1023 so that
 * the kernel is always mapped in every process.  These values are loaded
 * into the PD at pmap creation time.
 *
 * At any one time only one pmap can be active on a processor.  This is
 * the pmap whose PDP is pointed to by processor register %cr3.  This pmap
 * will have all its PTEs mapped into memory at the recursive mapping
 * point (slot #831 as show above).  When the pmap code wants to find the
 * PTE for a virtual address, all it has to do is the following:
 *
 * Address of PTE = (831 * 4MB) + (VA / PAGE_SIZE) * sizeof(pt_entry_t)
 *                = 0xcfc00000 + (VA / 4096) * 4
 *
 * What happens if the pmap layer is asked to perform an operation
 * on a pmap that is not the one which is currently active?  In that
 * case we take the PA of the PDP of the non-active pmap and put it in
 * slot 1023 of the active pmap.  This causes the non-active pmap's
 * PTEs to get mapped in the final 4MB of the 4GB address space
 * (e.g. starting at 0xffc00000).
 *
 * The following figure shows the effects of the recursive PDP mapping:
 *
 *   PDP (%cr3)
 *   +----+
 *   |   0| -> PTP#0 that maps VA 0x0 -> 0x400000
 *   |    |
 *   |    |
 *   | 831| -> points back to PDP (%cr3) mapping VA 0xcfc00000 -> 0xd0000000
 *   | 832| -> first kernel PTP (maps 0xd0000000 -> 0xe0400000)
 *   |    |
 *   |1023| -> points to alternate pmap's PDP (maps 0xffc00000 -> end)
 *   +----+
 *
 * Note that the PDE#831 VA (0xcfc00000) is defined as "PTE_BASE".
 * Note that the PDE#1023 VA (0xffc00000) is defined as "APTE_BASE".
 *
 * Starting at VA 0xcfc00000 the current active PDP (%cr3) acts as a
 * PTP:
 *
 * PTP#831 == PDP(%cr3) => maps VA 0xcfc00000 -> 0xd0000000
 *   +----+
 *   |   0| -> maps the contents of PTP#0 at VA 0xcfc00000->0xcfc01000
 *   |    |
 *   |    |
 *   | 831| -> maps the contents of PTP#831 (the PDP) at VA 0xcff3f000
 *   | 832| -> maps the contents of first kernel PTP
 *   |    |
 *   |1023|
 *   +----+
 *
 * Note that mapping of the PDP at PTP#831's VA (0xcff3f000) is
 * defined as "PDP_BASE".... within that mapping there are two
 * defines:
 *   "PDP_PDE" (0xcff3fcfc) is the VA of the PDE in the PDP
 *      which points back to itself.
 *   "APDP_PDE" (0xcff3fffc) is the VA of the PDE in the PDP which
 *      establishes the recursive mapping of the alternate pmap.
 *      To set the alternate PDP, one just has to put the correct
 *	PA info in *APDP_PDE.
 *
 * Note that in the APTE_BASE space, the APDP appears at VA
 * "APDP_BASE" (0xfffff000).
 */
{% endhighlight %}

# Attribution

The diagram for UVM's data structures comes from [Charles Craynor's paper at Usenix in 1999](http://usenix.org/legacy/publications/library/proceedings/usenix99/full_papers/cranor/cranor_html/index.html), of which there is also [a PDF version](https://www.usenix.org/event/usenix99/full_papers/cranor/cranor.pdf).
