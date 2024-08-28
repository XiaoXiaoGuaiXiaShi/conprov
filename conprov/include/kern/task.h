#ifndef __KERN_BPF_TASK_H
#define __KERN_BPF_TASK_H

#include "shared/prov_struct.h"
#include "shared/prov_types.h"
#include "kern/maps.h"
#include "kern/common.h"
#include "kern/node.h"

#define NULL ((void *)0)

// Update fields in a cred's provenance
static __always_inline void __update_cred(const struct task_struct *task,
                                             union prov_elt *prov) {
    prov->proc_info.pid = task->tgid;
    // char *comm = (char *)task->comm;
    // memcpy(&(prov->proc_info.comm), comm, sizeof(comm));
    prov->proc_info.cap_effective[0] = task->real_cred->cap_effective.cap[0];
    prov->proc_info.cap_effective[1] = task->real_cred->cap_effective.cap[1];
}

/* Update fields in a task's provenance detected by an LSM hook */
// TODO: further refactor this function.
static __always_inline void __update_task(const struct task_struct *task,
                                          union prov_elt *prov)
{
    prov->task_info.tid = task->pid;
	prov->task_info.pid = task->tgid;
    // prov->task_info.comm = task->comm;
    char *comm = (char *)task->comm;
    memcpy(&(prov->task_info.comm), comm, sizeof(comm));
    char *ccwd = (char *)task->fs->pwd.dentry->d_parent->d_iname;
    memcpy(&(prov->task_info.cwd), ccwd, sizeof(ccwd));
    // bpf_get_current_comm(&(prov->task_info.comm), TASK_COMM_LEN);

    prov->task_info.cap_effective[0] = task->real_cred->cap_effective.cap[0];
    prov->task_info.cap_effective[1] = task->real_cred->cap_effective.cap[1];
    // bpf_printk("11111111\n");
    // bpf_printk("prov->task_info.cap_effective[1]:%x\n", prov->task_info.cap_effective[1]);

    // namespaces
    prov->task_info.utsns = task->nsproxy->uts_ns->ns.inum;
    prov->task_info.userns = task->nsproxy->uts_ns->user_ns->ns.inum;
    prov->task_info.ipcns = task->nsproxy->ipc_ns->ns.inum;
    prov->task_info.mntns = task->nsproxy->mnt_ns->ns.inum;
    prov->task_info.pidns = task->thread_pid->numbers[0].ns->ns.inum;
    prov->task_info.netns = task->nsproxy->net_ns->ns.inum;
    prov->task_info.cgroupns = task->nsproxy->cgroup_ns->ns.inum;
}

static __always_inline union prov_elt *get_task_prov(struct task_struct *task)
{
    union prov_elt *prov;

    if (!task)
        return NULL;

    prov = bpf_task_storage_get(&task_storage_map, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);

    if (!prov)
        return NULL;
    if (!__set_initalized(prov))
        prov_init_node(prov, ACT_TASK);
    __update_task(task, prov);
    return prov;
}

#endif