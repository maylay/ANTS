#include <u.h>
#include <libc.h>
#include <venti.h>
#include <libsec.h>

#define MAGIC 0x54798314
#define NOTFREE(p)	assert((p)->magic == MAGIC)

struct Packet
{
	uchar *data;
	int len;
	void (*free)(void*);
	void *arg;
	int magic;
};

/*  Return a newly-allocated packet with no data */
Packet*
packetalloc(void)
{
	Packet *p;
	
	p = vtmalloc(sizeof *p);
	p->free = vtfree;
	p->magic = MAGIC;
	p->len = 0;
	p->data = p->arg = nil;
	return p;
}

/*  Release all resources associated with the packet. If p == nil, nop. */
void
packetfree(Packet *p)
{
	if(p == nil)
		return;
	NOTFREE(p);
	if(p->free == vtfree)
		memset(p->data, 0xFE, p->len);
	if(p->free != nil)
		p->free(p->arg);
	memset(p, 0xFB, sizeof *p);
	free(p);
}

/*  Construct a new packet whose data consists of this packet's data[offset..offset + n] */
/*  If unable to do so, return nil. */
Packet*
packetdup(Packet *p, int offset, int n)
{
	Packet *q;

	NOTFREE(p);
	if(offset < 0 || n < 0 || offset >= p->len || offset + n > p->len)
		return nil;
	q = packetalloc();
	packetappend(q, p->data+offset, n);
	return q;
}

/*  If n isn't a positive number, nop. */
/*  Append the first n bytes of buf to the end of the packet. */
void
packetappend(Packet *p, uchar *buf, int n)
{
	NOTFREE(p);
	if(n <= 0 || buf == nil)
		return;
	if(p->free != vtfree)
		sysfatal("packetappend");
	p->data = vtrealloc(p->data, p->len + n);
	p->arg = p->data;
	memmove(p->data + p->len, buf, n);
	p->len += n;
}

/*  Return the amount of allocated data. This is currently equal to the length. */
uint
packetasize(Packet *p)
{
	NOTFREE(p);
	return p->len;
}

int
packetcmp(Packet *p, Packet *q)
{
	int i, len;
	
	NOTFREE(p);
	NOTFREE(q);
	len = p->len;
	if(len > q->len)
		len = q->len;
	if(len && (i=memcmp(p->data, q->data, len)) != 0)
		return i;
	if(p->len > len)
		return 1;
	if(q->len > len)
		return -1;
	return 0;
}

/*  nop if q is empty */
/*  Otherwise, append q's data to p, and erase q (but do NOT free it). */
void
packetconcat(Packet *p, Packet *q)
{
	NOTFREE(p);
	NOTFREE(q);
	if(q->len == 0)
		return;
	packetappend(p, q->data, q->len);
	if(q->free == vtfree)
		memset(q->data, 0xFE, q->len);
	q->free(q->arg);
	q->free = nil;
	q->data = nil;
	q->arg = nil;
	q->len = 0;
}

/*  If buf exists, read n bytes from packet into buf and erase them from the packet. Return 0 on success and -1 on failure. */
int
packetconsume(Packet *p, uchar *buf, int n)
{
	NOTFREE(p);
	if(buf && packetcopy(p, buf, 0, n) < 0)
		return -1;
	return packettrim(p, n, p->len - n);
}

/*  Return -1 on failure and 0 on success. */
/*  Copy the packet's data[offset.. offset + n] to buf. */
int
packetcopy(Packet *p, uchar *buf, int offset, int n)
{
	NOTFREE(p);
	if(buf == nil || offset < 0 || n < 0 || offset >= p->len || offset + n > p->len)
		return -1;
	memmove(buf, p->data+offset, n);
	return 0;
}

Packet*
packetforeign(uchar *buf, int n, void (*free)(void*), void *a)
{
	Packet *p = packetalloc();
	p->data = buf;
	p->len = n;
	p->free = free;
	p->arg = a;
	return p;
}

/*  Return the amount of data read into IOchunks. */
/*  Assume nio == 1. */
/*  If no data to read, return 0. If error, return -1. */
int
packetfragments(Packet *p, IOchunk *io, int nio, int offset)
{
	NOTFREE(p);
	if(p->len == 0 || nio <= 0 || offset == p->len)
		return 0;
	if(offset < 0 || offset > p->len)
		return -1;
	io->addr = p->data + offset;
	io->len = p->len - offset;
	return io->len;
}

/*  Prepend buf[0..n] to the packet's data. */
void
packetprefix(Packet *p, uchar *buf, int n)
{
	NOTFREE(p);
	if(n <= 0 || buf == nil)
		return;
	if(p->free != vtfree)
		sysfatal("packetappend");
	p->data = vtrealloc(p->data, p->len+n);
	p->arg = p->data;
	memmove(p->data+n, p->data, p->len);
	memmove(p->data, buf, n);
	p->len += n;
}

void
packetsha1(Packet *p, uchar d[VtScoreSize])
{
	NOTFREE(p);
	sha1((uchar*)p->data, p->len, d, nil);
}

uint
packetsize(Packet *p)
{
	NOTFREE(p);
	return p->len;
}

/*  Return a new packet consisting ovf the first n bytes of the packet's data, consuming the data in the process. */
Packet*
packetsplit(Packet *p, int n)
{
	Packet *q;
	NOTFREE(p);
	if(n < 0 || n > p->len)
		return nil;
	q = packetalloc();
	if(n == 0)
		return q;
	q->data = vtmalloc(n);
	q->arg = q->data;
	q->free = vtfree;
	packetconsume(p, q->data, n);
	q->len = n;
	return q;
}

void
packetstats(void)
{
}

/*  Trim the packet to its data[offset..offset+n] */
int
packettrim(Packet *p, int offset, int n)
{
	NOTFREE(p);
	if(offset < 0 || n < 0 || offset > p->len || offset+ n > p->len)
		return -1;
	memmove(p->data, p->data+offset, n);
	p->data = vtrealloc(p->data, p->len);
	p->arg = p->data;
	p->len = n;
	return 0;
}

