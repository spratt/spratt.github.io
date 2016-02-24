---
published: false
title: Virtual Memory Differences
layout: post
tags: [OS, unix, BSD, memory, virtual memory, linux, solaris, sunos, openindiana]
---

Previously, we've been looking at [how POSIX specifies memory management](/2016/02/01/posix-memory-management/), [an academic design for virtual memory](/2016/02/07/radixVM/) and BSD virtual memory in particular:

1. [BSD Virtual Memory](/2016/02/02/BSD-virtual-memory/)
2. [OpenBSD Virtual Memory](/2016/02/23/OpenBSD-Virtual-Memory/)

Next, let's look at the differences between the virtual memory systems of NetBSD, OpenBSD, Linux, and OpenIndiana.

# History

First, let's give just a tiny summary of where each of these OSes come from.  We covered the history of BSD in the article on [BSD Virtual Memory](/2016/02/02/BSD-virtual-memory/), so I'll skip those.  If we go back to [the Wiki entry on the History of Unix](https://en.wikipedia.org/wiki/History_of_Unix), we can see that SunOS derived originally from BSD 3.0 to 4.1, then evolved alongside BSD until about the same time as BSD4.4.  At which point, Sun built a new OS called Solaris based on Unix System V.  Finally, OpenSolaris split from Solaris 10.  From [the Wiki entry on OpenIndiana](https://en.wikipedia.org/wiki/OpenIndiana), it seems to have come into existence when Sun was being acquired by Oracle.

As for Linux, the kernel was created in 1991 during the period immediately before 386BSD was first released.  At this time, people were becoming aware that the 386 was powerful enough to support some flavor of Unix, but nothing had yet been written.  It dovetailed perfectly with the GNU effort begun in 1983 to make a wholly free flavor of Unix.

# Differences

With the history out of the way, let's get into the differences.  They are the following:

- How the kernel deals with being out of memory
- Copy-on-write mechanisms
- How the kernel accesses user memory
- Dead queue (OpenBSD versus NetBSD)

## How the kernel deals with being out of memory

When OpenBSD's kernel runs out of memory, it simply panics.  I think the same is true of OpenIndiana.

Linux infamously has an Out-Of-Memory (OOM) killer.  This is a heuristic that runs when the kernel runs out of memory, and decides on a process to kill in order to free up memory.

## Copy-on-write mechanisms

## How the kernel accesses user memory

On Linux, the kernel maps all of physical memory into the kernel's address space.  This makes it possible to copy data from a user process into the kernel's memory without the overhead of first mapping the process' physical memory into the kernel's address space.  There's [a great article by IBM on how this works in linux](http://www.ibm.com/developerworks/library/l-kernel-memory-access/).

To figure out how this works on NetBSD, I found [an interesting article on linux compatibility on NetBSD](http://www.onlamp.com/pub/a/onlamp/2001/06/21/linux_bsd.html?page=3), which led me to the code for [the POSIX `read()` system call](http://pubs.opengroup.org/onlinepubs/9699919799/functions/read.html) in [`src/sys/kern/sys_generic.c`](http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/kern/sys_generic.c?rev=1.130&content-type=text/x-cvsweb-markup&only_with_tag=MAIN):

{% highlight C %}
/*
 * Read system call.
 */
/* ARGSUSED */
int
sys_read(struct lwp *l, const struct sys_read_args *uap, register_t *retval)
{
	/* {
		syscallarg(int)		fd;
		syscallarg(void *)	buf;
		syscallarg(size_t)	nbyte;
	} */
	file_t *fp;
	int fd;

	fd = SCARG(uap, fd);

	if ((fp = fd_getfile(fd)) == NULL)
		return (EBADF);

	if ((fp->f_flag & FREAD) == 0) {
		fd_putfile(fd);
		return (EBADF);
	}

	/* dofileread() will unuse the descriptor for us */
	return (dofileread(fd, fp, SCARG(uap, buf), SCARG(uap, nbyte),
	    &fp->f_offset, FOF_UPDATE_OFFSET, retval));
}
{% endhighlight %}

So that just calls `dofileread()` in the same file ([`src/sys/kern/sys_generic.c`](http://cvsweb.netbsd.org/bsdweb.cgi/src/sys/kern/sys_generic.c?rev=1.130&content-type=text/x-cvsweb-markup&only_with_tag=MAIN)):

{% highlight C %}
int
dofileread(int fd, struct file *fp, void *buf, size_t nbyte,
	off_t *offset, int flags, register_t *retval)
{
	struct iovec aiov;
	struct uio auio;
	size_t cnt;
	int error;
	lwp_t *l;

	l = curlwp;

	aiov.iov_base = (void *)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_READ;
	auio.uio_vmspace = l->l_proc->p_vmspace;

	/*
	 * Reads return ssize_t because -1 is returned on error.  Therefore
	 * we must restrict the length to SSIZE_MAX to avoid garbage return
	 * values.
	 */
	if (auio.uio_resid > SSIZE_MAX) {
		error = EINVAL;
		goto out;
	}

	cnt = auio.uio_resid;
	error = (*fp->f_ops->fo_read)(fp, offset, &auio, fp->f_cred, flags);
	if (error)
		if (auio.uio_resid != cnt && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
	cnt -= auio.uio_resid;
	ktrgenio(fd, UIO_READ, buf, cnt, error);
	*retval = cnt;
 out:
	fd_putfile(fd);
	return (error);
}
{% endhighlight %}

Actually, I think that the `SCARGS()` macro uses something like linux's `copy_from_user()` function, whose equivalent is [`copyin()` in NetBSD](http://nixdoc.net/man-pages/NetBSD/man9/copyout.9.html).  So the next step is to find where `SCARGS()` and `copyin()` are defined.

[Chuck Silvers' UBC paper](https://www.usenix.org/legacy/event/usenix2000/freenix/full_papers/silvers/silvers_html/) states the intention to implement `copyin()`/`copyout()` using UVM page loans.  Can't tell yet if this was implemented.

{% highlight C %}
{% endhighlight %}

{% highlight C %}
{% endhighlight %}

## Dead queue (OpenBSD versus NetBSD)

I've mostly been studying UVM since I began to study virtual memory.  When I began, I assumed that OpenBSD was mostly still running a VM system that was based on Cranor's UVM.  However, it seems that OpenBSD's VM system was substantially rewritten in 2011 by Ariane van der Steldt.

Ariane posted [a diff in OpenBSD's tech mailing list](http://openbsd-archive.7691.n7.nabble.com/vmmap-replacement-please-test-td169729.html) detailing a vmmap rewrite, and also made [a presentation about it](http://www.openbsd.org/papers/tdose_memalloc/presentation.html).

One of the changes Ariane made was to add a "dead entry queue," and as far as I can tell there is no official documentation about what a dead entry is.  We can see that [the dead entry queue was added in revision 1.45](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_map.h.diff?r1=text&tr1=1.44&r2=text&tr2=1.45) in [2011 by ariane](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_map.h?rev=1.45&content-type=text/x-cvsweb-markup).  This was part of Ariane's VM rewrite, so it isn't clear what the dead entry queue in particular was meant to do.

Since OpenBSD seems to differ significantly from Cranor's design, I'm going to switch to studying NetBSD instead.