#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>

#include "lock.h"

#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)
#define MAP_HUGE_16GB (34 << MAP_HUGE_SHIFT)

#define err(msg)	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define noinline	__attribute__((noinline))
#define barrier()	asm volatile("" ::: "memory")

#define SZ_KB	(1024UL)
#define SZ_MB	(SZ_KB*1024)
#define SZ_GB	(SZ_MB*1024)
#define SZ_TB	(SZ_GB*1024)

#define MEM_ALIGN (1UL*SZ_GB)

static unsigned long PAGE_SIZE;

#ifdef __powerpc__
#define cpu_relax()	asm volatile("nop" ::: "memory");
#define CACHE_LINE_SIZE 128
#else
#define cpu_relax()	asm volatile("nop" ::: "memory");
#define CACHE_LINE_SIZE 64
#endif

static int perf_fd;

struct perf_result {
	uint64_t value;
	uint64_t running;
	uint64_t enabled;
};

static void perf_setup(void)
{
	struct perf_event_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
//	attr.config = PERF_COUNT_HW_INSTRUCTIONS;
	attr.size = sizeof(attr);
	attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
				PERF_FORMAT_TOTAL_TIME_RUNNING;
	attr.disabled = 1;
//	attr.exclude_kernel = 1;
//	attr.exclude_hv = 1;
	attr.exclude_idle = 1;

	perf_fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
	if (perf_fd == -1)
		perror("perf_event_open");
}

static struct timespec perf_t1, perf_t2;

static uint64_t ts_delta_ns(struct timespec *t1, struct timespec *t2)
{
	return  (t2->tv_sec  - t1->tv_sec) * 1000000000UL +
		(t2->tv_nsec - t1->tv_nsec);
}

static void perf_start(void)
{
	if (perf_fd != -1) {
		ioctl(perf_fd, PERF_EVENT_IOC_RESET);
		prctl(PR_TASK_PERF_EVENTS_ENABLE);
	}
	clock_gettime(CLOCK_MONOTONIC, &perf_t1);
}

static void perf_stop(uint64_t *ns, uint64_t *cycles)
{
	struct perf_result result;
	int rc;

	clock_gettime(CLOCK_MONOTONIC, &perf_t2);
	if (perf_fd != -1) {
		prctl(PR_TASK_PERF_EVENTS_DISABLE);
		rc = read(perf_fd, &result, sizeof(result));
		if (rc != sizeof(result))
			err("read perf result");
		*cycles = result.value;
	}

	*ns = ts_delta_ns(&perf_t1, &perf_t2);
}

static void set_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);

	if (sched_setaffinity(0, sizeof(set), &set) == -1)
		err("sched_setaffinity");
}

#define MAX_CONCURRENCY 2048

static pid_t procs[MAX_CONCURRENCY];
static pthread_t threads[MAX_CONCURRENCY];
static pthread_mutex_t ctrl_mutex;
static pthread_cond_t ctrl_cond;
static int nr_started;
static bool use_procs = false;
static bool verbose_result = false;

struct ctrl {
	volatile bool started[MAX_CONCURRENCY] __attribute__((aligned(128)));
	volatile bool pre_start[MAX_CONCURRENCY] __attribute__((aligned(128)));
	volatile uint32_t finished[MAX_CONCURRENCY] __attribute__((aligned(128)));
	volatile bool pre;
	volatile bool start;
	volatile bool stop;
	volatile bool finish;
	volatile bool procs;

	int cpu[MAX_CONCURRENCY];

	void *mem;
	size_t size;
	size_t snoop_size;
	volatile bool run;
	void *priv_mem[MAX_CONCURRENCY];
	struct random_data random_data[MAX_CONCURRENCY];
	unsigned long iters_completed[MAX_CONCURRENCY];
};

static struct ctrl *ctrl;

static void (*pre_work)(int nr);
static void (*work)(int nr);

static noinline void work_fn(int nr)
{
	if (pre_work) {
		ctrl->pre_start[nr] = 1;

		while (!ctrl->pre)
			cpu_relax();

		pre_work(nr);
	}

	if (!use_procs) {
		pthread_mutex_lock(&ctrl_mutex);
		nr_started++;
		pthread_mutex_unlock(&ctrl_mutex);
	}

	ctrl->started[nr] = 1;

	while (!ctrl->start)
		cpu_relax();

	work(nr);

	ctrl->finished[nr] = 1;
	wakeval(&ctrl->finished[nr]);

	if (!use_procs) {
		pthread_mutex_lock(&ctrl_mutex);
		nr_started--;
		if (nr_started == 0) {
			pthread_cond_signal(&ctrl_cond);
		}
		pthread_mutex_unlock(&ctrl_mutex);
	}

	while (!ctrl->stop)
		cpu_relax();
}

static void *thread_fn(void *arg)
{
	int i = (int)(unsigned long)arg;

	work_fn(i);
}

static void create_threads(int nr, int *list)
{
//	struct sched_param param = { .sched_priority = 0 };
	pthread_attr_t attr;
	cpu_set_t set;
	unsigned long i, ns;

	if (nr >= MAX_CONCURRENCY) {
		fprintf(stderr, "Threads exceed MAX_CONCURRENCY\n");
		exit(1);
	}

	ctrl = mmap(NULL, sizeof(struct ctrl), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	memset(ctrl, 0, sizeof(struct ctrl));

	ctrl->procs = use_procs;

//	param.sched_priority = sched_get_priority_min(SCHED_FIFO);

//	if (sched_setscheduler(0, SCHED_FIFO, &param) == -1)
//		err("sched_setscheduler");

	if (ctrl->procs) {
		for (i = 0; i < nr; i++) {
			int cpu = list[i];

			ctrl->cpu[i] = cpu;

			set_cpu(cpu);

			procs[i] = fork();
			if (procs[i] == -1) {
				perror("fork");
				exit(EXIT_FAILURE);
			}
			if (!procs[i]) {
				set_cpu(cpu);
				work_fn(i);
				exit(EXIT_SUCCESS);
			}
		}

	} else {
		if (pthread_attr_init(&attr) != 0)
			err("pthread_attr_init");

		for (i = 0; i < nr; i++) {
			int cpu = list[i];

			ctrl->cpu[i] = cpu;

			set_cpu(cpu);

			CPU_ZERO(&set);
			CPU_SET(cpu, &set);

			if (pthread_attr_setaffinity_np(&attr, sizeof(set), &set) != 0)
				err("pthread_attr_setaffinity_np");

			if (pthread_create(&threads[i], &attr, thread_fn, (void *)(unsigned long)i) != 0)
				err("pthread_create");
		}
	}

	for (i = 0; i < nr; i++) {
		if (pre_work) {
			while (!ctrl->pre_start[i])
				sched_yield();
		} else {
			while (!ctrl->started[i])
				sched_yield();
		}
	}
}

static void prestart_threads(int nr)
{
	int i;

	ctrl->pre = 1;
	for (i = 0; i < nr; i++) {
		while (!ctrl->started[i])
			sched_yield();
	}
}

static void start_threads(int nr)
{
	ctrl->start = 1;
}

static void wait_threads(int nr)
{
	int i;

	ctrl->finish = 1;

	if (!use_procs) {
		pthread_mutex_lock(&ctrl_mutex);
		while (nr_started) {
			pthread_cond_wait(&ctrl_cond, &ctrl_mutex);
		}
		pthread_mutex_unlock(&ctrl_mutex);
	}

	for (i = 0; i < nr; i++) {
		while (!ctrl->finished[i]) {
			waitval(&ctrl->finished[i], 0);
//			cpu_relax();
		}
	}

	ctrl->stop = 1;
}

static void stop_threads(int nr)
{
	int i;

	for (i = 0; i < nr; i++) {
//		pthread_kill(threads[i], SIGKILL);
		if (ctrl->procs) {
			if (waitpid(procs[i], NULL, 0) == -1) {
				perror("waitpid");
				exit(EXIT_FAILURE);
			}
		} else {
			pthread_join(threads[i], NULL);
		}
	}

	munmap(ctrl, sizeof(struct ctrl));

	work = NULL;
	pre_work = NULL;
}

static bool use_huge_page = false;
static bool use_huge_2mb = true;
static bool use_huge_1gb = false;

static void *alloc_mem(size_t size)
{
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	void *mem;

	if (use_huge_page) {
		flags |= MAP_HUGETLB;
		if (use_huge_1gb)
			flags |= MAP_HUGE_1GB;
		else if (use_huge_2mb)
			flags |= MAP_HUGE_2MB;
	}

	mem = mmap(0, size, PROT_READ|PROT_WRITE, flags, -1, 0);
	if (mem == MAP_FAILED) {
		flags = MAP_ANONYMOUS | MAP_PRIVATE;
		mem = mmap(0, size, PROT_READ|PROT_WRITE, flags, -1, 0);
		if (mem == MAP_FAILED) {
			fprintf(stderr, "could not allocate memory\n");
			exit(1);
		}

		if (use_huge_page) {
			if (madvise(mem, size, MADV_HUGEPAGE) == -1) {
				perror("madvise");
				exit(1);
			}
		} else {
			if (madvise(mem, size, MADV_NOHUGEPAGE) == -1) {
				perror("madvise");
				exit(1);
			}
		}
	}

	memset(mem, 0, size);

	return mem;
}

static void free_mem(void *mem, size_t size)
{
	if (munmap(mem, size) == -1) {
		perror("munmap");
		exit(1);
	}
}

struct node {
	struct node *parent;
	struct node *left;
	struct node *right;
	unsigned val;
};

static struct node *rotate(struct node **root, struct node *node, bool left)
{
	struct node *g = node->parent;
	struct node *s, *c;

	if (left) {
		s = node->right;
		c = s->left;
		node->right = c;
		if (c)
			c->parent = node;
		s->left = node;
		node->parent = s;
		s->parent = g;
	} else {
		s = node->left;
		c = s->right;
		node->left = c;
		if (c)
			c->parent = node;
		s->right = node;
		node->parent = s;
		s->parent = g;
	}

	if (g) {
		if (g->left == node)
			g->left = s;
		else
			g->right = s;
	} else {
		*root = s;
	}

	return s;
}

static void _insert(struct node **nodep, struct node *parent, struct node *node)
{
	if (*nodep == NULL) {
		node->parent = parent;
		*nodep = node;
		return;
	}

	parent = *nodep;

	if (node->val < parent->val)
		_insert(&parent->left, parent, node);
	else
		_insert(&parent->right, parent, node);

}

static void insert(struct node **root, struct node *node)
{
	node->left = node->right = node->parent = NULL;
	_insert(root, NULL, node);
}

static struct node *find(struct node *root, unsigned val)
{
	if (!root)
		return NULL;
	if (val < root->val)
		return find(root->left, val);
	else if (val > root->val)
		return find(root->right, val);
	else
		return root;
}

struct node *tree_root = NULL;

static void fill_mem(void *mem, size_t size)
{
	size_t nr = size / sizeof(struct node);
	size_t alloc = 0;
	int i;

	for (i = 0; i < nr; i++) {
		struct node *node = mem + alloc;
		alloc += sizeof(struct node);

		node->val = random() % nr;
		insert(&tree_root, node);
	}
}

static void search_mem(void *mem, int nr, size_t size)
{
	size_t sz = size / sizeof(struct node);
	int32_t result;

	random_r(&ctrl->random_data[nr], &result);

	find(tree_root, (unsigned int)result % sz);
}

struct rl {
	struct timespec start;
	int per_sec;
};

static void rl_start(struct rl *rl, int per_sec)
{
	rl->per_sec = per_sec;

	if (!per_sec)
		return;

	clock_gettime(CLOCK_MONOTONIC, &rl->start);
}

static void rl_end(struct rl *rl)
{
	struct timespec t;
	uint64_t ns;
	uint64_t ns_per;

	if (!rl->per_sec)
		return;

	ns_per = 1000000000UL / rl->per_sec;
	do {
		clock_gettime(CLOCK_MONOTONIC, &t);
	} while (ts_delta_ns(&rl->start, &t) < ns_per);
}

static int nr_tlbi_cpus;
static int *tlbi_cpulist;
static int nr_snoop_cpus;
static int *snoop_cpulist;
static int nr_cpus;
static int *cpulist;

static int runtime = 5;
static size_t nr_pages = 0;
static size_t snoop_working_set = 0;

static int tlbi_per_sec = 0;
enum tlbi_strategy {
	TLBI_PAGE,
	TLBI_ALL,
};
static int tlbi_strategy = TLBI_PAGE;
static int tlbi_prot = PROT_READ|PROT_WRITE|PROT_EXEC;

enum snoop_work {
	SNOOP_NOOP,
	SNOOP_MEMSET,
	SNOOP_SHARED_MEMSET,
	SNOOP_MEMCPY,
	SNOOP_SEARCH,
	SNOOP_INV_LOCK,
	SNOOP_SHARED_LOCK,
	SNOOP_LOCK,
};
static int snoop_work = SNOOP_SEARCH;

static void *my_snooper_fn(void *arg)
{
	int nr = (long)arg;
	int cpu = snoop_cpulist[nr];

	set_cpu(cpu);

	while (!ctrl->finished[nr]) {
		/*
		 * Need to keep the thread running otherwise it gets trimmed
		 * out of the mm cpumask, so can't wait here.
		 */
//		waitval(&ctrl->finished[nr], 0);
		cpu_relax();
	}
}

static void tlbi_pre_work(int nr)
{
	void *mem = ctrl->mem;
	size_t size = ctrl->size;
	size_t snoop_size = ctrl->snoop_size;

	if (nr < nr_tlbi_cpus) {
		if (use_procs) {
			pthread_t my_snooper;

			/*
			 * In process mode, a single snooper per process is
			 * created.
			 */
			if (pthread_create(&my_snooper, NULL, my_snooper_fn, (void *)(long)nr) != 0)
				err("pthread_create");
		}
	} else {
		/* Arbitrary snoopers only supported with threaded */
		assert(!use_procs);
		if (snoop_work == SNOOP_MEMCPY || snoop_work == SNOOP_MEMSET) {
			ctrl->priv_mem[nr] = alloc_mem(size);
		}
		if (snoop_work == SNOOP_SEARCH) {
			ctrl->priv_mem[nr] = malloc(1024);
			initstate_r(nr, ctrl->priv_mem[nr], 1024, &ctrl->random_data[nr]);
			search_mem(mem, nr, snoop_size);
			search_mem(mem, nr, snoop_size);
			search_mem(mem, nr, snoop_size);
			search_mem(mem, nr, snoop_size);
			search_mem(mem, nr, snoop_size);
		}
	}
}

static unsigned long shared_lock __attribute__((aligned(128)));

static void tlbi_work(int nr)
{
	void *mem = ctrl->mem;
	size_t size = ctrl->size;
	size_t snoop_size = ctrl->snoop_size;
	size_t iters = 0;

	if (nr < nr_tlbi_cpus) {
		size_t s = size;
		void *m = mem;

		if (!use_procs) {
			s = size / nr_tlbi_cpus;
			m = mem + s * nr;
		}

		while (ctrl->run) {
			struct rl rl;

			if (tlbi_strategy == TLBI_PAGE) {
				size_t j;

				for (j = 0; j < s; j += PAGE_SIZE) {
					rl_start(&rl, tlbi_per_sec);

					if (mprotect(m + j, PAGE_SIZE, tlbi_prot) == -1) {
						perror("mprotect");
						exit(1);
					}
					if (mprotect(m + j, PAGE_SIZE, PROT_READ|PROT_WRITE) == -1) {
						perror("mprotect");
						exit(1);
					}

					rl_end(&rl);

					iters++;
				}
			} else {
				rl_start(&rl, tlbi_per_sec);

				if (mprotect(m, s, tlbi_prot) == -1) {
					perror("mprotect");
					exit(1);
				}
				if (mprotect(m, s, PROT_READ|PROT_WRITE) == -1) {
					perror("mprotect");
					exit(1);
				}

				rl_end(&rl);

				iters++;
			}
		}
	} else {
		unsigned long private_lock;

		while (ctrl->run) {
			if (snoop_work == SNOOP_MEMSET) {
				memset(ctrl->priv_mem[nr], nr, snoop_size);
			} else if (snoop_work == SNOOP_SHARED_MEMSET) {
				memset(mem, nr, snoop_size);
			} else if (snoop_work == SNOOP_SEARCH) {
				search_mem(mem, nr, snoop_size);
			} else if (snoop_work == SNOOP_MEMCPY) {
				memcpy(ctrl->priv_mem[nr], mem, snoop_size);
			} else if (snoop_work == SNOOP_LOCK) {
				lock(&private_lock);
				unlock(&private_lock);
			} else if (snoop_work == SNOOP_SHARED_LOCK) {
				lock(&shared_lock);
				unlock(&shared_lock);
			} else if (snoop_work == SNOOP_INV_LOCK) {
				lock(mem);
				unlock(mem);
			} else if (snoop_work == SNOOP_NOOP) {
				barrier();
			}
			iters++;
		}
	}

	ctrl->iters_completed[nr] = iters;
}

static void SIGSEGV_handler(int sig)
{
}

static void SIGALRM_handler(int sig)
{
	ctrl->run = false;
}

static void print_help(void)
{
	printf("Usage: tlbi_test [OPTION]...\n");
	printf("Exercise TLB invalidation via mprotect(2) system calls.\n");
	printf("  Pages are divided between tlbi CPUs, and used by all snooper CPUs.\n");
	printf("  Snoopers may not be used when using processes.\n");
	printf("Options:\n");
	printf("  --use_procs              test uses processes (default threads)\n");
	printf("  --runtime=T              test runtime, in seconds (default 5)\n");
	printf("  --pages=P                pages to allocate (default 1 per tlbi CPU, or 1 if no tlbi CPUs)\n");
	printf("  --tlbi_cpulist=CPULIST   CPUs to run tlbi threads on (default none)\n");
	printf("  --snoop_cpulist=CPULIST  CPUs to run snoop threads on (default none)\n");
	printf("  --tlbi_ratelimit=RATE    Limit each tlbi CPU, rate per second (default no limit)\n");
	printf("  --tlbi_strategy=S        tlbi strategy (default page)\n");
	printf("                page: mprotect individual pages\n");
	printf("                 all: mprotect all pages\n");
	printf("  --tlbi_prot=P            tlbi protection mprotect (default x)\n");
	printf("                none: PROT_NONE (all accesses fault)\n");
	printf("                   x: PROT_READ|PROT_WRITE|PROT_EXEC (exec clear drives invalidate)\n");
	printf("                  ro: PROT_READ (stores fault)\n");
	printf("                  rw: PROT_READ|PROT_WRITE (no-op, no tlbies issued)\n");
	printf("  --snoop_work=W           snoop work (default search)\n");
	printf("                noop: loop no memory accesses (except trivial ifetch)\n");
	printf("              memset: store to per-thread memory (not subject to tlbi)\n");
	printf("       shared_memset: store to all primary working set\n");
	printf("              memcpy: memcpy load all primary working set, store to per-thread memory (not subject to tlbi)\n");
	printf("              search: random binary tree search in primary working set\n");
	printf("   invalidating_lock: perform spin lock/unlock on first dword in primary working set\n");
	printf("         shared_lock: perform spin lock/unlock to shared dword (not in working set)\n");
	printf("                lock: perform spin lock/unlock to per-thread memory\n");
	printf("  --snoop_working_set=WS   working set size (bytes) for memset (default same size as primary working set)\n");
}

static void parse_cpulist(const char *str, int *nr, int **cpus)
{
	const char *ptr = str;

	*nr = 0;
	*cpus = NULL;

	for (;;) {
		char *endptr;
		long c;

		if (strlen(ptr) == 0)
			break;

		c = strtol(ptr, &endptr, 10);

		if (endptr == ptr)
			goto err;

		if (c < 0) /* || c > max cpus? */
			goto err;

		if (*endptr == ',' || *endptr == '\0') {
			*nr = *nr + 1;
			*cpus = realloc(*cpus, *nr * sizeof(int));
			(*cpus)[*nr - 1] = c;
		} else if (*endptr == '-') {
			long e, i;

			ptr = endptr + 1;
			if (strlen(ptr) == 0)
				goto err;

			e = strtol(ptr, &endptr, 10);

			if (endptr == ptr)
				goto err;

			if (e < 0) /* || c > max cpus? */
				goto err;

			if (e <= c)
				goto err;

			if (!(*endptr == ',' || *endptr == '\0'))
				goto err;

			for (i = c; i <= e; i++) {
				*nr = *nr + 1;
				*cpus = realloc(*cpus, *nr * sizeof(int));
				(*cpus)[*nr - 1] = i;
			}

		} else {
			goto err;
		}

		ptr = endptr;
		if (*ptr == ',')
			ptr++;
	}

	return;

err:
	fprintf(stderr, "Bad CPU list %s\n", str);
	exit(1);
}

static void getopts(int argc, char *argv[])
{
	const char *name;

	for (;;) {
		int option_index;
		int c;
		struct option long_options[] = {
			{"use_procs",		no_argument, 0, 0 },
			{"verbose_result",	no_argument, 0, 0 },
			{"runtime",		required_argument, 0, 0 },
			{"pages",		required_argument, 0, 0 },
			{"tlbi_cpulist",	required_argument, 0, 0 },
			{"snoop_cpulist",	required_argument, 0, 0 },
			{"tlbi_ratelimit",	required_argument, 0, 0 },
			{"tlbi_strategy",	required_argument, 0, 0 },
			{"tlbi_prot",		required_argument, 0, 0 },
			{"snoop_work",		required_argument, 0, 0 },
			{"snoop_working_set",	required_argument, 0, 0 },
			{0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		if (c == '?') {
			print_help();
			exit(1);
		}

		if (c == ':') {
			print_help();
			exit(1);
		}

		if (c != 0) {
			fprintf(stderr, "getopt_long: unknown return value %d\n", c);
			print_help();
			exit(1);
		}

		name = long_options[option_index].name;
		if        (!strcmp(name, "use_procs")) {
			use_procs = true;

		} else if (!strcmp(name, "verbose_result")) {
			verbose_result = true;

		} else if (!strcmp(name, "runtime")) {
			char *endptr;
			runtime = strtol(optarg, &endptr, 0);
			if (runtime <= 0 || optarg == endptr || strlen(endptr) != 0)
				goto badopt;

		} else if (!strcmp(name, "pages")) {
			char *endptr;
			nr_pages = strtol(optarg, &endptr, 0);
			if (nr_pages <= 0 || optarg == endptr || strlen(endptr) != 0)
				goto badopt;

		} else if (!strcmp(name, "tlbi_cpulist")) {
			parse_cpulist(optarg, &nr_tlbi_cpus, &tlbi_cpulist);

		} else if (!strcmp(name, "snoop_cpulist")) {
			parse_cpulist(optarg, &nr_snoop_cpus, &snoop_cpulist);

		} else if (!strcmp(name, "tlbi_ratelimit")) {
			char *endptr;
			tlbi_per_sec = strtol(optarg, &endptr, 0);
			if (tlbi_per_sec < 0 || optarg == endptr || strlen(endptr) != 0)
				goto badopt;

		} else if (!strcmp(name, "tlbi_strategy")) {
			if (!strcmp(optarg, "page"))
				tlbi_strategy = TLBI_PAGE;
			else if (!strcmp(optarg, "all"))
				tlbi_strategy = TLBI_ALL;
			else
				goto badopt;

		} else if (!strcmp(name, "tlbi_prot")) {
			if (!strcmp(optarg, "none"))
				tlbi_prot = PROT_NONE;
			else if (!strcmp(optarg, "x"))
				tlbi_prot = PROT_READ|PROT_WRITE|PROT_EXEC;
			else if (!strcmp(optarg, "ro"))
				tlbi_prot = PROT_READ;
			else if (!strcmp(optarg, "rw"))
				tlbi_prot = PROT_READ | PROT_WRITE;
			else
				goto badopt;

		} else if (!strcmp(name, "snoop_work")) {
			if (!strcmp(optarg, "noop"))
				snoop_work = SNOOP_NOOP;
			else if (!strcmp(optarg, "memset"))
				snoop_work = SNOOP_MEMSET;
			else if (!strcmp(optarg, "shared_memset"))
				snoop_work = SNOOP_SHARED_MEMSET;
			else if (!strcmp(optarg, "memcpy"))
				snoop_work = SNOOP_MEMCPY;
			else if (!strcmp(optarg, "search"))
				snoop_work = SNOOP_SEARCH;
			else if (!strcmp(optarg, "invalidating_lock"))
				snoop_work = SNOOP_INV_LOCK;
			else if (!strcmp(optarg, "shared_lock"))
				snoop_work = SNOOP_SHARED_LOCK;
			else if (!strcmp(optarg, "lock"))
				snoop_work = SNOOP_LOCK;
			else
				goto badopt;

		} else if (!strcmp(name, "snoop_working_set")) {
			char *endptr;
			snoop_working_set = strtol(optarg, &endptr, 0);
			if (snoop_working_set <= 0 || optarg == endptr || strlen(endptr) != 0)
				goto badopt;

		} else {
			printf("Unknown option %s", name);
			if (optarg)
				printf(" %s", optarg);
			printf("\n");
			print_help();
			exit(1);
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Unknown parameter %s\n", argv[optind]);
		print_help();
		exit(1);
	}

	if (nr_pages == 0)
		nr_pages = nr_tlbi_cpus;
	if (nr_pages == 0)
		nr_pages = 1;

	nr_cpus = nr_tlbi_cpus + nr_snoop_cpus;
	if (nr_cpus == 0) {
		fprintf(stderr, "Error: must specify at least one CPU\n");
		exit(1);
	}

	if (use_procs) {
		if (nr_snoop_cpus != nr_tlbi_cpus) {
			fprintf(stderr, "Error: use_procs must provide the same number of CPUs for snoopers as tlbi\n");
			exit(1);
		}
		if (snoop_work != SNOOP_NOOP) {
			fprintf(stderr, "Error: use_procs must use noop snoop work\n");
			exit(1);
		}

		/* Main harness doens't try to start the snoopers */
		nr_cpus -= nr_snoop_cpus;
		nr_snoop_cpus = 0;
	}

	cpulist = malloc(nr_cpus * sizeof(int));
	memcpy(cpulist, tlbi_cpulist, nr_tlbi_cpus * sizeof(int));
	memcpy(cpulist + nr_tlbi_cpus, snoop_cpulist, nr_snoop_cpus * sizeof(int));

	return;

badopt:
	fprintf(stderr, "Bad argument to option %s (%s)\n", name, optarg);
	print_help();
	exit(1);
}

static void print_runtime(void)
{
	int i;

	printf("Running tlbi_test\n");
	printf("System page size:	%lu bytes\n", PAGE_SIZE);
	printf("Runtime:		%d seconds\n", runtime);
	printf("Primary working set:	%lu pages\n", nr_pages);

	printf("tlbi threads:		%d\n", nr_tlbi_cpus);
	if (nr_tlbi_cpus) {
		printf("tlbi CPUs:		");
		for (i = 0; i < nr_tlbi_cpus; i++)
			printf("%d ", tlbi_cpulist[i]);
		printf("\n");

		if (tlbi_per_sec)
			printf("tlbi ratelimit:		%d per sec per thread\n", tlbi_per_sec);
		printf("tlbi strategy		%s\n", (tlbi_strategy == TLBI_PAGE ? "page" : "all"));
		printf("tlbi prot		%s\n", (tlbi_prot == PROT_NONE ? "none" : (tlbi_prot == PROT_READ ? "ro" : (tlbi_prot == PROT_READ|PROT_WRITE|PROT_EXEC ? "x" : "rw"))));
	}

	if (use_procs)
		nr_snoop_cpus = nr_tlbi_cpus; /* hack to make it print */
	printf("snoop threads:		%d\n", nr_snoop_cpus);
	if (nr_snoop_cpus) {
		printf("snoop CPUs:		");
		for (i = 0; i < nr_snoop_cpus; i++)
			printf("%d ", snoop_cpulist[i]);
		printf("\n");

		printf("snoop work:		");
		switch(snoop_work) {
		case SNOOP_NOOP:
			printf("noop\n");
			break;
		case SNOOP_MEMSET:
			printf("memset\n");
			break;
		case SNOOP_SHARED_MEMSET: /* XXX: invalidating and shared */
			printf("shared memset\n");
			break;
		case SNOOP_MEMCPY:
			printf("memcpy\n");
			break;
		case SNOOP_SEARCH:
			printf("search\n");
			break;
		case SNOOP_INV_LOCK: /* XXX invalidating and shared */
			printf("invalidating lock\n");
			break;
		case SNOOP_SHARED_LOCK:
			printf("shared lock\n");
			break;
		case SNOOP_LOCK:
			printf("lock\n");
			break;
		default:
			printf("unknown\n");
		}

		switch(snoop_work) {
		case SNOOP_MEMSET:
			printf("snoop working set size: %lu bytes per worker\n", snoop_working_set);
			break;
		case SNOOP_SHARED_MEMSET:
		case SNOOP_SEARCH:
			printf("snoop working set size: %lu bytes all workers\n", snoop_working_set);
			break;
		case SNOOP_MEMCPY:
			printf("snoop working set size: %lu bytes all workers + %lu bytes per worker\n", snoop_working_set, snoop_working_set);
			break;
		default:
			break;
		}
	}
	if (use_procs)
		nr_snoop_cpus = 0; /* hack */
}

int main(int argc, char *argv[])
{
	struct sigaction act;
	uint64_t ns, cycles;
	void *mem;
	size_t size;

	PAGE_SIZE = sysconf(_SC_PAGE_SIZE);

	getopts(argc, argv);

	size = nr_pages * PAGE_SIZE;
	if (snoop_working_set == 0)
		snoop_working_set = size;

	print_runtime();

	set_cpu(0);

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIGSEGV_handler;
	if (sigaction(SIGSEGV, &act, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	act.sa_handler = SIGALRM_handler;
	if (sigaction(SIGALRM, &act, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	mem = alloc_mem(size);

	if (nr_snoop_cpus > 0 && snoop_work == SNOOP_SEARCH)
		fill_mem(mem, snoop_working_set);

	perf_setup();

	pre_work = tlbi_pre_work;
	work = tlbi_work;

	create_threads(nr_cpus, cpulist);
	ctrl->mem = mem;
	ctrl->size = size;
	ctrl->snoop_size = snoop_working_set;
	ctrl->run = true;
	prestart_threads(nr_cpus);

	alarm(runtime);
	perf_start();
	start_threads(nr_cpus);
	wait_threads(nr_cpus);
	perf_stop(&ns, &cycles);
	{
		int i;

		printf("Result:\n");
		if (nr_tlbi_cpus) {
			uint64_t ops = 0;
			for (i = 0; i < nr_tlbi_cpus; i++)
				ops += ctrl->iters_completed[i];
			printf("   tlbi threads  % 10.0lf op/s\n", (double)ops / ((double)ns / 1000000000.0f));
			printf("     per thread  % 10.0lf op/s (% 10.1lf ns/op)\n", (double)ops / nr_tlbi_cpus / ((double)ns / 1000000000.0f), (double)ns / (ops / nr_tlbi_cpus));
		}

		if (nr_snoop_cpus) {
			uint64_t ops = 0;
			for (i = 0; i < nr_snoop_cpus; i++)
				ops += ctrl->iters_completed[nr_tlbi_cpus + i];
			printf("  snoop threads  % 10.0lf op/s\n", (double)ops / ((double)ns / 1000000000.0f));
			printf("     per thread  % 10.0lf op/s (% 10.1lf ns/op)\n", (double)ops / nr_snoop_cpus / ((double)ns / 1000000000.0f), (double)ns / (ops / nr_snoop_cpus));
		}

		if (verbose_result) {
			for (i = 0; i < nr_tlbi_cpus; i++) {
				uint64_t op = ctrl->iters_completed[i];
				printf("   tlbi thread %u % 10.0lf op/s (% 10.1lf ns/op)\n", i, (double)op / ((double)ns / 1000000000.0f), (double)ns / op);
			}
			for (i = 0; i < nr_snoop_cpus; i++) {
				uint64_t op = ctrl->iters_completed[nr_tlbi_cpus + i];
				printf("  snoop thread %u % 10.0lf op/s (% 10.1lf ns/op)\n", i, (double)op / ((double)ns / 1000000000.0f), (double)ns / op);
			}
		}
	}
	stop_threads(nr_cpus);
}

