#ifndef _NC_SHMTX_H_INCLUDED_
#define _NC_SHMTX_H_INCLUDED_

typedef long                        nc_atomic_int_t;
typedef unsigned long               nc_atomic_uint_t;


typedef volatile nc_atomic_uint_t  nc_atomic_t;


#define nc_atomic_cmp_set(lock, old, set)                                    \
    __sync_bool_compare_and_swap(lock, old, set)

#define nc_atomic_fetch_add(value, add)                                      \
    __sync_fetch_and_add(value, add)

#define nc_memory_barrier()        __sync_synchronize()







#endif

