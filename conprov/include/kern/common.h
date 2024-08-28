#ifndef __KERN_BPF_COMMON_H
#define __KERN_BPF_COMMON_H

#include "kern/maps.h"
#include "shared/prov_struct.h"

static __always_inline bool __set_initalized(union prov_elt *prov)
{
    bool is_initialized;
    is_initialized = provenance_is_initialized(prov);
    if (!is_initialized)
        set_initialized(prov);
    return is_initialized;
}

static __always_inline uint64_t prov_next_id(uint32_t key)
{
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if (!val)
        return 0;
    __sync_fetch_and_add(&val->id, 1);
    // TODO: eBPF seems to have issue with __sync_fetch_and_add
    // TODO: we cannot obtain the return value of the function.
    // TODO: Perhaps we need a lock to avoid race conditions.
    return val->id;
}

static __always_inline uint64_t prov_get_id(uint32_t key)
{
    struct id_elem *val = bpf_map_lookup_elem(&ids_map, &key);
    if (!val)
        return 0;
    return val->id;
}

static __always_inline bool __set_name(union prov_elt *prov)
{
    bool is_named;
    is_named = provenance_is_named(prov);
    if (!is_named)
        set_named(prov);
    return is_named;
}

#endif