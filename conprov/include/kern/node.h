#ifndef __KERN_BPF_NODE_H
#define __KERN_BPF_NODE_H

#include "shared/prov_struct.h"
#include "shared/id.h"

/* Initialize common fields of a node's provenance */
static __always_inline void prov_init_node(union prov_elt *node, uint64_t type)
{
    node_identifier(node).type = type;
    node_identifier(node).id = prov_next_id(NODE_ID_INDEX);
}

#endif
