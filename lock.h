#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

static int futex(uint32_t *uaddr, int futex_op, uint32_t val,
		const struct timespec *timeout, uint32_t uaddr2, uint32_t val3)
{
	return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

static void waitval(volatile uint32_t *mem, uint32_t val)
{
	if (futex((uint32_t *)mem, FUTEX_WAIT, val, NULL, 0, 0) == -1) {
		if (errno == EAGAIN)
			return;
		if (errno == EINTR)
			return;

		perror("futex wait");
		exit(1);
	}
}

static void wakeval(volatile uint32_t *mem)
{
	if (futex((uint32_t *)mem, FUTEX_WAKE, INT_MAX, NULL, 0, 0) == -1) {
		perror("futex wake");
		exit(1);
	}
}


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


