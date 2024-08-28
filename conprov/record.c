#include <syslog.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "usr/record.h"
#include "usr/configuration.h"
#include "usr/spade.h"
#include "usr/types.h"
#include "shared/prov_types.h"

static struct provenance_ops prov_ops;
extern configuration __config;
static int __log_fd;
static pthread_mutex_t __file_lock;

void init(void)
{
    return;
}

void log_error(char *error)
{
    syslog(LOG_ERR, "From library: %s", error);
}

struct provenance_ops null_ops = {
    .init = &init,
    .log_derived = NULL,
    .log_generated = NULL,
    .log_used = NULL,
    .log_informed = NULL,
    .log_influenced = NULL,
    .log_associated = NULL,
    .log_proc = NULL,
    .log_task = NULL,
    .log_inode = NULL,
    .log_msg = NULL,
    .log_shm = NULL,
    .log_packet = NULL,
    .log_address = NULL,
    .log_file_name = NULL,
    .log_xattr = NULL,
    .log_packet_content = NULL,
    .log_arg = NULL,
    .log_machine = NULL,
    .log_error = &log_error,
};

void spade_derived(struct relation_struct* relation){
  spade_json_append(derived_to_spade_json(relation));
}

void spade_generated(struct relation_struct* relation){
  spade_json_append(generated_to_spade_json(relation));
}

void spade_used(struct relation_struct* relation){
  spade_json_append(used_to_spade_json(relation));
}

void spade_informed(struct relation_struct* relation){
  spade_json_append(informed_to_spade_json(relation));
}

void spade_influenced(struct relation_struct* relation){
  spade_json_append(influenced_to_spade_json(relation));
}

void spade_associated(struct relation_struct* relation){
  spade_json_append(associated_to_spade_json(relation));
}

void spade_proc(struct proc_prov_struct* proc){
    spade_json_append(proc_to_spade_json(proc));
}

void spade_task(struct task_prov_struct* task){
  spade_json_append(task_to_spade_json(task));
}

void spade_inode(struct inode_prov_struct* inode){
  spade_json_append(inode_to_spade_json(inode));
}

void spade_file_name(struct file_name_struct* f_name){
    spade_json_append(pathname_to_spade_json(f_name));
}

void spade_address(struct address_struct* address){
  spade_json_append(addr_to_spade_json(address));
}

struct provenance_ops spade_ops = {
    .init = &init,
    .log_derived = &spade_derived,
    .log_generated = &spade_generated,
    .log_used = &spade_used,
    .log_informed = &spade_informed,
    .log_influenced = &spade_influenced,
    .log_associated = &spade_associated,
    .log_proc = &spade_proc,
    .log_task = &spade_task,
    .log_inode=&spade_inode,
    .log_address=&spade_address,
    .log_file_name = &spade_file_name,
    .log_error = &log_error,
};

void relation_record(union long_prov_elt *msg)
{
    uint64_t type = prov_type(msg);

    if (prov_is_used(type))
    {
        if (prov_ops.log_used != NULL)
            prov_ops.log_used(&(msg->relation_info));
    }
    else if (prov_is_informed(type))
    {
        if (prov_ops.log_informed != NULL)
            prov_ops.log_informed(&(msg->relation_info));
    }
    else if (prov_is_generated(type))
    {
        if (prov_ops.log_generated != NULL)
            prov_ops.log_generated(&(msg->relation_info));
    }
    else if (prov_is_derived(type))
    {
        if (prov_ops.log_derived != NULL)
            prov_ops.log_derived(&(msg->relation_info));
    }
    else if (prov_is_influenced(type))
    {
        if (prov_ops.log_influenced != NULL)
            prov_ops.log_influenced(&(msg->relation_info));
    }
    else if (prov_is_associated(type))
    {
        if (prov_ops.log_associated != NULL)
            prov_ops.log_associated(&(msg->relation_info));
    }
    else
        syslog(LOG_ERR, "ProvBPF: unknown relation type %lu.", prov_type(msg));
}

void node_record(union prov_elt *msg)
{
    switch (prov_type(msg))
    {
    case ACT_TASK:
        if (prov_ops.log_task != NULL)
            prov_ops.log_task(&(msg->task_info));
        break;
    case ENT_PROC:
      if(prov_ops.log_proc!=NULL)
        prov_ops.log_proc(&(msg->proc_info));
      break;
    case ENT_INODE_SOCKET:
      if(prov_ops.log_inode!=NULL)
        prov_ops.log_inode(&(msg->inode_info));
      break;
    case ENT_INODE_FILE:
        if(prov_ops.log_inode!=NULL)
            prov_ops.log_inode(&(msg->inode_info));
        break;
    case ENT_INODE_CHAR:
        if(prov_ops.log_inode!=NULL)
            prov_ops.log_inode(&(msg->inode_info));
        break;
    case ENT_INODE_PIPE:
        if(prov_ops.log_inode!=NULL)
            prov_ops.log_inode(&(msg->inode_info));
        break;
    case ENT_INODE_UNKNOWN:
        if(prov_ops.log_inode!=NULL)
            prov_ops.log_inode(&(msg->inode_info));
        break;
    default:
        syslog(LOG_ERR, "ProvBPF: unknown node type %lu.", prov_type(msg));
        break;
    }
}

void long_prov_record(union long_prov_elt *msg)
{
    switch (prov_type(msg))
    {
    case ENT_PATH:
        if (prov_ops.log_file_name != NULL)
            prov_ops.log_file_name(&(msg->file_name_info));
        break;
    case ENT_ADDR:
        if(prov_ops.log_address!=NULL)
            prov_ops.log_address(&(msg->address_info));
        break;
    default:
        syslog(LOG_ERR, "ProvBPF: unknown node long type %lx.", prov_type(msg));
        break;
    }
}

static int __log_fd;
static pthread_mutex_t __file_lock;

static inline void log_to_file(char *json)
{
    int len = strlen(json);
    int rc;

    pthread_mutex_lock(&__file_lock);
    while (len > 0)
    {
        rc = write(__log_fd, json, len);
        if (rc < 0)
            exit(-1);
        json += rc;
        len -= rc;
    }
    rc = write(__log_fd, "\n", 1);
    if (rc < 0)
        exit(-1);
    fsync(__log_fd);
    pthread_mutex_unlock(&__file_lock);
}

void prov_record_init()
{
    /* setup log file */
    syslog(LOG_INFO, "ProvBPF: Log file %s.", __config.log_path);
    __log_fd = open(__config.log_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (__log_fd < 0)
    {
        syslog(LOG_ERR, "ProvBPF: Cannot open log file.");
        exit(-1);
    }
    lseek(__log_fd, 0, SEEK_SET);

    if (pthread_mutex_init(&__file_lock, NULL) != 0)
    {
        syslog(LOG_ERR, "ProvBPF: File mutex init failed.");
        exit(-1);
    }

    /* ready the recording hooks */
    memcpy(&prov_ops, &spade_ops, sizeof(struct provenance_ops));
    set_SPADEJSON_callback(log_to_file);
}

void bpf_prov_record(union long_prov_elt *msg)
{
    if (prov_is_relation(msg))
    {
        relation_record(msg);
    }
    else
    {
        if (prov_type_is_long(node_type(msg)))
        {
            long_prov_record(msg);
        }
        else
        {
            node_record((union prov_elt *)msg);
        }
    }
}

void prov_refresh_records(void)
{
    sleep(1);
    flush_spade_json();
}