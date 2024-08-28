#ifndef __KERN_BPF_RECORD_H
#define __KERN_BPF_RECORD_H

#include "shared/prov_struct.h"
#include <bpf/bpf_helpers.h>
#include "kern/maps.h"
#include "kern/common.h"

static __always_inline bool filter_update_node(const uint64_t relation_type)
{
    if (relation_type == RL_VERSION_TASK)
        return true;
    if (relation_type == RL_VERSION)
        return true;
    if (relation_type == RL_NAMED)
        return true;
    return false;
}

static __always_inline void write_to_rb(union prov_elt *prov)
{
    if (!prov)
        return;
    bpf_ringbuf_output(&r_buf, prov, sizeof(union prov_elt), 0);
}

static __always_inline void write_node(union prov_elt *node)
{
    if (provenance_is_recorded(node))
        return;
    write_to_rb(node);
    set_prov_recorded(node);
}

/* Initialize common fields of a node's provenance */
static __always_inline void prov_init_relation(union prov_elt *prov,
                                               uint64_t type,
                                               const struct file *file,
                                               const int cap,
                                               const uint64_t flags,
                                               const long sysid)
{
    // loff_t offset;
    relation_identifier(prov).type = type;
    relation_identifier(prov).id = prov_next_id(RELATION_ID_INDEX);
    if (file)
    {
        prov->relation_info.set = FILE_INFO_SET;
        // offset = file->f_pos;
        // prov->relation_info.offset = offset;
    }
    prov->relation_info.flags = flags;
    prov->relation_info.cap = cap;
    prov->relation_info.syscall_nid = sysid;
}

// record a graph relation
static __always_inline void __write_relation(const uint64_t type,
                                             union prov_elt *from,
                                             union prov_elt *to,
                                             const struct file *file,
                                             const int cap,
                                             const uint64_t flags,
                                             const long sysid)
{
    int map_id = RELATION_PERCPU_TMP;
    union prov_elt *relation = bpf_map_lookup_elem(&tmp_prov_elt_map, &map_id);

    if (!relation)
        return;

    prov_init_relation(relation, type, file, cap, flags, sysid);

    // set send node
    __builtin_memcpy(&(relation->relation_info.snd), &node_identifier(from), sizeof(union prov_identifier));
    // set rcv node
    __builtin_memcpy(&(relation->relation_info.rcv), &node_identifier(to), sizeof(union prov_identifier));
    // record relation provenance
    write_to_rb(relation);
}

static __always_inline void __update_version(const uint64_t type,
                                             union prov_elt *prov)
{
    union prov_elt old_prov;

    // if there are no outgoing edge we do not need to update
    if (!provenance_has_outgoing(prov))
        return;
    // some type of relation should not generate updates
    if (filter_update_node(type))
        return;

    __builtin_memcpy(&old_prov, prov, sizeof(union prov_elt));
    // Update the version of prov to the newer version
    node_identifier(prov).version++;
    clear_prov_recorded(prov);

    // Record the version relation between two versions of the same identity.
    if (node_identifier(prov).type == ACT_TASK)
    {
        __write_relation(RL_VERSION_TASK, &old_prov, prov, NULL, 1000, 0, 1000);
    }
    else
    {
        __write_relation(RL_VERSION, &old_prov, prov, NULL, 1000, 0, 1000);
    }
    // Newer version now has no outgoing edge
    clear_has_outgoing(prov);
}

// record a graph relation
static __always_inline void __record_relation(const uint64_t type,
                                              union prov_elt *from,
                                              union prov_elt *to,
                                              const struct file *file,
                                              const int cap,
                                              const uint64_t flags,
                                              const long sysid)
{
    // do not repeat redundant edges
    if (node_previous_id(to) == node_identifier(from).id && node_previous_type(to) == type)
        return;
    
    node_previous_id(to) = node_identifier(from).id;
    node_previous_type(to) = type;
    // we update the destination node
    __update_version(type, to);
    // the source has an outgoing edge
    set_has_outgoing(from);
    write_node(from);
    write_node(to);
    __write_relation(type, from, to, file, cap, flags, sysid);
}

static __always_inline void derives(uint64_t type,
                                     union prov_elt *from,
                                     union prov_elt *to,
                                     const struct file *file,
                                     const uint64_t flags) {
   __record_relation(type, from, to, file, 1000, flags, 1000);
}

static __always_inline void informs(uint64_t type,
                                    union prov_elt *from,
                                    union prov_elt *to,
                                    const struct file *file,
                                    const int cap,
                                    const uint64_t flags)
{
    __record_relation(type, from, to, file, cap, flags, 1000);
}

static __always_inline void record_terminate(const uint64_t type,
                                             union prov_elt *prov)
{
    union prov_elt old_prov;

    __builtin_memcpy(&old_prov, prov, sizeof(union prov_elt));
    // Update the version of prov to the newer version
    node_identifier(prov).version++;
    clear_prov_recorded(prov);
    __write_relation(type, &old_prov, prov, NULL, 1000, 0, 1000);
}

static __always_inline void generates(const uint64_t type,
                                      struct task_struct *current,
                                      union prov_elt *activity,
                                      union prov_elt *entity,
                                      union prov_elt *activity_mem,
                                      const struct file *file,
                                      const uint64_t flags)
{
    // update shared
    __record_relation(RL_PROC_READ, activity_mem, activity, NULL, 1000, 0, 1000);
    __record_relation(type, activity, entity, file, 1000, flags, 1000);
}

static __always_inline void uses(const uint64_t type,
                                 struct task_struct *current,
                                 union prov_elt *entity,
                                 union prov_elt *activity,
                                 union prov_elt *activity_mem,
                                 const struct file *file,
                                 const uint64_t flags) {
    __record_relation(type, entity, activity, file, 1000, flags, 1000);
    __record_relation(RL_PROC_WRITE, activity, activity_mem, NULL, 1000, 0, 1000);
}
// record a graph relation
static __always_inline void __record_relation_ls(const uint64_t type,
                                             union long_prov_elt *from,
                                             union prov_elt *to,
                                             const struct file *file,
                                             const uint64_t flags)
{
    // do not repeat redundant edges
	if (node_previous_id(to) == node_identifier(from).id && node_previous_type(to) == type)
		return;

	node_previous_id(to) = node_identifier(from).id;
	node_previous_type(to) = type;
    // we update the destination node
    __update_version(type, to);

    bpf_ringbuf_output(&r_buf, from, sizeof(union long_prov_elt), 0);
    write_node(to);
    __write_relation(type, (union prov_elt *)from, to, file, 1000, flags, 1000);
}

#endif