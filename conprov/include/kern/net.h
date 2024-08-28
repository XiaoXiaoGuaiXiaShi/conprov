#ifndef __KERN_BPF_PROVENANCE_NET_H
#define __KERN_BPF_PROVENANCE_NET_H

#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "shared/prov_struct.h"
#include "kern/maps.h"

#define PF_LOCAL	1	/* Local to host (pipes and file-domain).  */
#define PF_INET		2	/* IP protocol family.  */
#define PF_UNIX		PF_LOCAL /* POSIX name for PF_LOCAL.  */
#define AF_INET		PF_INET
#define AF_UNIX		PF_UNIX

static __always_inline void record_address(struct sockaddr *address, int addrlen, union prov_elt *prov) {
	int map_id = ADDRESS_PERCPU_LONG_TMP;
	union long_prov_elt *aprov = bpf_map_lookup_elem(&long_tmp_prov_map, &map_id);
	if (!aprov)
		return;

	prov_init_node((union prov_elt *)aprov, ENT_ADDR);

    // copy each type of address
    // TODO expand to more types
    // char *addr_str = (char *) BPF_CORE_READ(address, sa_data); 
    sa_family_t sa_family = (sa_family_t)BPF_CORE_READ(address, sa_family); 
	// bpf_probe_read_str(&(pprov->file_name_info.name), PATH_MAX, name);
	if (sa_family == AF_INET)
        bpf_probe_read_kernel(aprov->address_info.addr, sizeof(struct sockaddr_in), address);
    else if (sa_family == AF_INET)
        bpf_probe_read_kernel(aprov->address_info.addr, sizeof(struct sockaddr_in6), address);
    else if (sa_family == AF_UNIX)
        bpf_probe_read_kernel(aprov->address_info.addr, sizeof(struct sockaddr_un), address);
    else
        bpf_probe_read_kernel(aprov->address_info.addr, sizeof(struct sockaddr), address);

    __record_relation_ls(RL_ADDRESSED, aprov, prov, NULL, 0);
}

#endif