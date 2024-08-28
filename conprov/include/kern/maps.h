#ifndef __KERN_BPF_MAPS_H
#define __KERN_BPF_MAPS_H

#include "shared/prov_struct.h"
#include "shared/id.h"

#define MAX_ENTRIES 8 * 1024
#define PATH_PERCPU_LONG_TMP 2
#define ADDRESS_PERCPU_LONG_TMP 0

/* BPF ringbuf map */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    /* NOTE: The minimum size seems to be 1 << 12.
     * Any value smaller than this results in
     * runtime error. */
    __uint(max_entries, 1 << 24);
} r_buf SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct process_event);
} processes SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct namespace_info);
} nsinfos SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
} cgroup_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, union prov_elt);
} task_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, union prov_elt);
} inode_storage_map SEC(".maps");

#define TASK_PERCPU_TMP 1
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ID_MAX_ENTRY);
    __type(key, uint32_t);
    __type(value, union prov_elt);
} cp_task_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ID_MAX_ENTRY);
    __type(key, uint32_t);
    __type(value, struct id_elem);
} ids_map SEC(".maps");

#define RELATION_PERCPU_TMP 0

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ID_MAX_ENTRY);
    __type(key, uint32_t);
    __type(value, union prov_elt);
} tmp_prov_elt_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ID_MAX_ENTRY);
    __type(key, uint32_t);
    __type(value, union long_prov_elt);
} long_tmp_prov_map SEC(".maps");

#endif