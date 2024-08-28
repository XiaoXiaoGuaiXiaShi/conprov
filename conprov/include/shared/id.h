#ifndef __CAMFLOW_BPF_ID_H
#define __CAMFLOW_BPF_ID_H

#include "shared/prov_struct.h"

struct id_elem
{
    uint64_t id;
};

#define RELATION_ID_INDEX 0
#define NODE_ID_INDEX 1
#define BOOT_ID_INDEX 2
#define MACHINE_ID_INDEX 3

#define ID_MAX_ENTRY 4

#endif
