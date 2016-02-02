---
published: false
title: BSD Virtual Memory
layout: post
tags: [OS, unix, BSD, memory]
---
After [the article on POSIX memory management](/2016/02/01/posix-memory-management/), we have a good grasp of the high-level memory allocation functions specified in [POSIX.1](http://pubs.opengroup.org/onlinepubs/9699919799/).  We learned how `malloc` is a C library function which can be implemented using `mmap`.  Now it's time to dive into the details about how `mmap` is implemented.  POSIX.1 doesn't specify implementation details like that, so we have to pick a particular operating system to investigate.  For historical reasons, I chose BSD.

# BSD History

UNIX was started at Bell Labs in 1969.  In 1974, UC Berkeley received a copy of UNIX which they ran on a PDP-11.  In 1975, they installed UNIX v6.  By 1977, they had written enough software in which other Universities were interested that they started bundling it together as BSD.

