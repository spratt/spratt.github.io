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

- the Out-Of-Memory Killer (only on Linux)
- Copy-On-Write mechanisms
- how the kernel accesses user memory
- dead queue (OpenBSD versus NetBSD)

## OOM Killer

## Copy-On-Write

## kernel accessing user memory

## Dead Queue

We can see that [the dead entry queue was added in revision 1.45](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_map.h.diff?r1=text&tr1=1.44&r2=text&tr2=1.45) in [2011 by ariane](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_map.h?rev=1.45&content-type=text/x-cvsweb-markup).  This revision changes a lot of things, so it isn't clear what the dead entry queue was meant to do.
