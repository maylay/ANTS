#include <u.h>
#include <libc.h>
#include <venti.h>

void
vtfree(void *p)
{
	free(p);
}

void *
vtmalloc(ulong size)
{
	void *p;

	p = malloc(size);
	if(p == 0)
		sysfatal("vtmalloc: out of memory");
	setmalloctag(p, getcallerpc(&size));
	return p;
}

void *
vtmallocz(ulong size)
{
	void *p = vtmalloc(size);
	memset(p, 0, size);
	setmalloctag(p, getcallerpc(&size));
	return p;
}

void *
vtrealloc(void *p, ulong size)
{
	if(p == nil)
		return vtmalloc(size);
	p = realloc(p, size);
	if(p == 0)
		sysfatal("vtMemRealloc: out of memory");
	setrealloctag(p, getcallerpc(&size));
	return p;
}

void *
vtbrk(ulong n)
{
	void *p;
	p = sbrk(n);
	if(p == (void*)-1)
		sysfatal("sbrk failed and venti's memory allocation is shit");
	memset(p, 0, n);
	return p;
}

