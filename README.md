# tlbi_test

tlbi_test attempts to drive TLB invalidation using mprotect(2) system calls
in a multi-threaded program, and measure performance of various simple
loads.

The primary working set pages are divided between tlbi threads, and are
subject to mprotect. snooper threads do not issue tlbis, but they run
and thus become targets of the invalidations, and they can perform some
workloads (either on the primary working set or their own private working
sets or both) which may influence the performance of the tlbie threads.

```Usage: tlbi_test [OPTION]...
Exercise TLB invalidation via mprotect(2) system calls.
  Pages are divided between tlbi CPUs, and used by all snooper CPUs.
Options:
  --runtime=T              test runtime, in seconds (default 5)
  --pages=P                pages to allocate (default 1 per tlbi CPU, or 1 if no tlbi CPUs)
  --tlbi_cpulist=CPULIST   CPUs to run tlbi threads on (default none)
  --snoop_cpulist=CPULIST  CPUs to run snoop threads on (default none)
  --tlbi_ratelimit=RATE    Limit each tlbi CPU, rate per second (default no limit)
  --tlbi_strategy=S        tlbi strategy (default page)
            page: mprotect individual pages
             all: mprotect all pages
  --tlbi_prot=P            tlbi protection mprotect (default ro)
            none: PROT_NONE (all accesses fault)
              ro: PROT_READ (stores fault)
              rw: PROT_READ|PROT_WRITE (no-op, no tlbies issued)
  --snoop_work=W           snoop work (default search)
            noop: loop no memory accesses (except trivial ifetch)
          memset: store to all primary working set
          memcpy: memcpy load all primary working set, store to per-thread memory (not subject to tlbi)
          search: random binary tree search in primary working set
            lock: perform spin lock/unlock on first dword in primary working set```
