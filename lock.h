#ifdef __powerpc__
static inline void inc(unsigned long *mem)
{
	unsigned long t;

	asm volatile(
"1:	lwarx	%0,0,%2		# inc\n\
	addi	%0,%0,1\n\
	stwcx.	%0,0,%2 \n\
	bne-	1b"
	: "=&r" (t), "+m" (*mem)
	: "r" (mem)
	: "cc");
}

static inline void lock(unsigned long *mem)
{
	unsigned long prev, new = 1;

	__asm__ __volatile__ (
"1:	ldarx	%0,0,%2,1	# lock\n\
	cmpdi	%0,0\n\
	bne-	1b\n\
	stdcx.	%3,0,%2\n\
	bne-	1b\n\
	lwsync \n\
2:"
	: "=&r" (prev), "+m" (*mem)
	: "r" (mem), "r" (new)
	: "cc", "memory");
}

static inline void unlock(unsigned long *mem)
{
	unsigned long new = 0;

	__asm__ __volatile__ (
"	lwsync\n\
	std	%2,%0\n\
"
	: "+m" (*mem)
	: "r" (mem), "r" (new) : "memory");
}
#else
static inline unsigned long inc(unsigned long *mem)
{
	asm volatile("lock ; addl %1,%0"
			: "+m" (*mem) : "ri"(1));
}

static inline unsigned long cmpxchg(unsigned long *mem, unsigned long old, unsigned long new)
{
	unsigned long ret;

	asm volatile("lock ; cmpxchgq %2, %1"
			: "=a" (ret), "+m" (*mem)
			: "r" (new), "0" (old));

	return ret;
}

static inline void lock(unsigned long *mem)
{
	while (cmpxchg(mem, 0, 1) != 0)
		;
}

static inline void unlock(unsigned long *mem)
{
	asm volatile("" ::: "memory");
	*mem = 0;
	asm volatile("" ::: "memory");
}
#endif


