# tlbi_test

tlbi_test attempts to drive TLB invalidation using mprotect(2) system calls
in a multi-threaded program, and measure performance of various simple
loads.

The primary working set pages are divided between tlbi threads, and are
subject to mprotect. snooper threads do not issue tlbis, but they run
and thus become targets of the invalidations, and they can perform some
workloads (either on the primary working set or their own private working
sets or both) which may influence the performance of the tlbie threads.

