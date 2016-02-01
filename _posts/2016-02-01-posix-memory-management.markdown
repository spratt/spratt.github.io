---
published: true
title: POSIX Memory Management
layout: post
tags: [OS, unix, posix, memory]
---

As an application programmer using a unix-flavored operating system,
one's view of memory management is usually limited to `malloc` and its
various alternative forms.  However, `malloc` is part of the C
standard library and while it is specified as part of
[POSIX.1](http://pubs.opengroup.org/onlinepubs/9699919799/), the
specification defers to the ISO C standard.  In fact, since `malloc`
is part of the C standard library it is not a part of the kernel and
can't allocate memory directly.  For that, we need to use kernel
functions.

[The Single UNIX Specification](), which eventually became the POSIX.1
specification, specifies both
[`sbrk`](http://pubs.opengroup.org/onlinepubs/7908799/xsh/brk.html)
and
[`mmap`](http://pubs.opengroup.org/onlinepubs/007908799/xsh/mmap.html)
for allocating memory.  But `sbrk` was [allegedly removed in
POSIX.1-2001](http://stackoverflow.com/questions/6988487/what-does-brk-system-call-do),
and certainly we can see it no longer exists in [the version of
POSIX.1-2004 still available
online](http://pubs.opengroup.org/cgi/kman2.cgi?value=sbrk).  To
understand what they do and why `sbrk` was probably removed, we need
to understand how a program's code and data are laid out in memory.

# Memory Layout

![](https://upload.wikimedia.org/wikipedia/commons/thumb/7/70/Typical_computer_data_memory_arrangement.png/161px-Typical_computer_data_memory_arrangement.png)

Modern operating systems implement virtual memory, which gives each
application the illusion that each has access to all (or most) of the
machine's physical memory.  In reality, the kernel maps virtual memory
locations to physical ones and, with help from the CPU, translates
virtual to physical addresses on the fly.  Since we ostensibly have
the entire address space in which to arrange our code and data, this
gives us a lot of flexibility.

The diagram on the right shows a pretty typical way to arrange the
code and data for a program.  Starting at the bottom (which has the
lowest memory address), we have the text region.  This is where a
prorgam's code would be stored.  Above that is the [BSS (Block Started
by Symbol) region](https://en.wikipedia.org/wiki/.bss) and above that
is the initialized data region, which are where static variables
(uninitialized and initialized, respectively) are stored.  Above that,
we have the heap, free memory, and the stack.

Any standard C course will explain the difference between the stack
and the heap.  The stack contains variables like function arguments
and variables defined locally within a function.  These variables are
automatically pushed onto the stack when a function is called, and are
popped off the stack when the function returns a value.  In order to
keep a variable around for longer than the life of a function call, we
need to allocate on the heap.

Keep in mind that this memory layout is only the typical case.  An OS
that implements the POSIX.1 specification may not lay out memory in
the same way.

# `sbrk`

The [`brk` and `sbrk` kernel
functions](http://pubs.opengroup.org/onlinepubs/7908799/xsh/brk.html)
move the boundary between the heap and free memory, effectively
increasing the size of the heap and allocating more memory for a
program.  In particular, `brk` takes a memory address and sets that as
the new "break" (the byte past the last heap-allocated memory),
whereas `sbrk` more usefully takes a number of bytes and increases the
size of the heap by that many bytes.  We can effectively decrease the
size of the heap by giving `sbrk` a negative value.

We could get away with only using this function if we treated the heap
as another stack.  In other words, if we always deallocated in the
reverse order as we allocated memory, then we could easily just use
`sbrk`.

However, it's much more useful as an application programmer to be able
to allocate and deallocate from the heap in any order.  For this
reason, when `malloc` is implemented using `sbrk`, it usually
allocates more space than it needs and uses something like a
linked-list to keep track of unused memory locations.

A naive implementation of `malloc` might assume that no programmer
would both use `malloc` and call `sbrk` directly, so the specification
warns that the behavior of `sbrk` is unspecified if an application
also uses any other functions (such as `malloc` or `mmap`).

Notice that `sbrk` makes this strong assumption that the heap is a
contiguous area of memory with a single boundary which can grow or
shrink to allocate more or less memory to a process.  This, and that
`sbrk` doesn't play well with `malloc`, are probably why even the
first version of POSIX.1 removed `sbrk`, though most unix-flavored
OSes typically still implement it.  Thankfully, we have a nice
alternative: `mmap`.

ASIDE: For more on implementing `malloc` using `sbrk`, there's [a
great code review cleaning up the `malloc` implementation from
K&R](https://stackoverflow.com/questions/13159564/explain-this-implementation-of-malloc-from-the-kr-book/13159565#13159565)
which uses a function `morecore` which seems to be analagous to
`sbrk`.  There's also [a high-level view of how malloc
works](http://jamesgolick.com/2013/5/15/memory-allocators-101.html),
as well as [a tutorial on implementing a simple version of
malloc](http://danluu.com/malloc-tutorial/) based on [a tutorial on
implmeneting a complex version of
malloc](http://www.inf.udec.cl/~leo/Malloc_tutorial.pdf).

# `mmap`

[`mmap` is specified in the latest version of the POSIX.1
specification.](http://pubs.opengroup.org/onlinepubs/9699919799/functions/mmap.html)
Its brief description is "The mmap() function shall establish a
mapping between an address space of a process and a memory object."
Immediately, we can see that this doesn't make any assumptions about
how a program is laid out in memory.  Although at first glance, it may
seem that this function is more about mapping something like I/O into
the address space of a process.

The function prototype for `mmap` is:

~~~
void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
~~~

The specification also goes on to state that if `addr` is 0, and
`FLAG_FIXED` is not set, then the implementation is free to find
unused memory into which to map.  Also, most operating systems have an
additional flag `MAP_ANON` which effectively just allocates the
desired memory in the same way that `malloc` would, without making any
assumptions about memory layout.  To illustrate this, we can implement
a very rudimentary version of `malloc` using only `mmap` (and `munmap`
to implement `free`).

{% highlight C 44 %}
#include <sys/mman.h>
#include <stdio.h>

void* mymalloc(size_t len) {
  void* addr = mmap(0,                      // addr
                    len + sizeof(size_t),   // len
                    PROT_READ | PROT_WRITE, // prot
                    MAP_ANON | MAP_PRIVATE, // flags
                    -1,                     // filedes
                    0);                     // off
  *(size_t*)addr = len;
  return addr + sizeof(size_t);
}

int myfree(void* addr) {
  return munmap(addr - sizeof(size_t),      // addr
                (size_t) addr);             // len
}

int main(int argc, char* argv[]) {
  puts("Allocating first integer...\n");
  int* heap_integer_1 = mymalloc(sizeof(int));
  puts("Allocating char...\n");
  char* heap_char_1 = mymalloc(sizeof(char));
  puts("Allocating second integer...\n");
  int* heap_integer_2 = mymalloc(sizeof(int));
  puts("Writing to char...\n");
  *heap_char_1 = 'o';
  puts("Writing to first integer...\n");
  *heap_integer_1 = 1111;
  puts("Writing to second integer...\n");
  *heap_integer_2 = 2222;
  puts("Reading from allocated integers...");
  printf("First allocated integer:  %d\n", *heap_integer_1);
  printf("Heap allocated char:      %c\n", *heap_char_1);
  printf("Second allocated integer: %d\n", *heap_integer_2);
  puts("Deallocating second integer...");
  myfree(heap_integer_2);
  puts("Deallocating char...");
  myfree(heap_char_1);
  puts("Deallocating first integer...");
  myfree(heap_integer_1);
  return 0;
}
{% endhighlight %}

You can [run this code online at codepad](http://codepad.org/NTnpRMCz).

# Attribution

The memory arrangement diagram is by Majenko (Own work) [CC BY-SA
4.0](http://creativecommons.org/licenses/by-sa/4.0), via Wikimedia
Commons.  It appears on [the Wikipedia page for the data
segment](https://en.wikipedia.org/wiki/Data_segment).
