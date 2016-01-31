---
published: false
title: BSD Memory Management
layout: post
tags: [OS, BSD, memory]
---
As an application programmer using a unix-flavored operating system, one's view of memory management is usually limited to `malloc` and its various alternative forms.

```
MALLOC(3)                BSD Library Functions Manual                MALLOC(3)

NAME
     calloc, free, malloc, realloc, reallocf, valloc -- memory allocation

SYNOPSIS
     #include <stdlib.h>

     void *
     calloc(size_t count, size_t size);

     void
     free(void *ptr);

     void *
     malloc(size_t size);

     void *
     realloc(void *ptr, size_t size);

     void *
     reallocf(void *ptr, size_t size);

     void *
     valloc(size_t size);

DESCRIPTION
     The malloc(), calloc(), valloc(), realloc(), and reallocf() functions
     allocate memory.  [...]  The
     free() function frees allocations that were created via the preceding
     allocation functions.

     The malloc() function allocates size bytes of memory and returns a
     pointer to the allocated memory.
```

But `malloc` is a 