#ifndef RECORD_H
#define RECORD_H

#include "shared/prov_struct.h"

extern char *ro_path;

struct provenance_ops
{
    void (*init)(void);
    bool (*filter)(prov_entry_t *msg);
    void (*received_prov)(union prov_elt *);
    void (*received_long_prov)(union long_prov_elt *);
    /* relation callback */
    void (*log_derived)(struct relation_struct *);
    void (*log_generated)(struct relation_struct *);
    void (*log_used)(struct relation_struct *);
    void (*log_informed)(struct relation_struct *);
    void (*log_influenced)(struct relation_struct *);
    void (*log_associated)(struct relation_struct *);
    /* nodes callback */
    void (*log_proc)(struct proc_prov_struct *);
    void (*log_task)(struct task_prov_struct *);
    void (*log_inode)(struct inode_prov_struct *);
    void (*log_msg)(struct msg_msg_struct *);
    void (*log_shm)(struct shm_struct *);
    void (*log_packet)(struct pck_struct *);
    void (*log_address)(struct address_struct *);
    void (*log_file_name)(struct file_name_struct *);
    void (*log_xattr)(struct xattr_prov_struct *);
    void (*log_packet_content)(struct pckcnt_struct *);
    void (*log_arg)(struct arg_struct *);
    void (*log_machine)(struct machine_struct *);
    /* callback for library errors */
    void (*log_error)(char *);
    /* is it filter only? for query framework */
    bool is_query;
};

void prov_record_init(void);
void bpf_prov_record(union long_prov_elt *msg);
void prov_refresh_records(void);
#endif