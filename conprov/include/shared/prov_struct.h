#ifndef _PROVSTRUCT_H
#define _PROVSTRUCT_H

#define FLOW_ALLOWED 0
#define FLOW_DISALLOWED 1

#define FILE_INFO_SET 0x01

#define bool signed char

#ifndef __int8_t_defined
#define __int8_t_defined
typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;
#if __WORDSIZE == 64
typedef long int int64_t;
#else
__extension__ typedef long long int int64_t;
#endif
#endif

typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
#ifndef __uint32_t_defined
typedef unsigned int uint32_t;
#define __uint32_t_defined
#endif
#if __WORDSIZE == 64
typedef unsigned long int uint64_t;
#else
__extension__ typedef unsigned long long int uint64_t;
#endif

#define MAX_STRING_SIZE 64        /* max bytes in pathname */

struct node_identifier
{
    uint64_t type;
    uint64_t id;
    uint32_t version;
};

struct relation_identifier
{
    uint64_t type;
    uint64_t id;
};

struct packet_identifier
{
    uint64_t type;
    uint16_t id;
    uint32_t snd_ip;
    uint32_t rcv_ip;
    uint16_t snd_port;
    uint16_t rcv_port;
    uint8_t protocol;
    uint32_t seq;
};

#define MAX2(a, b) ((a > b) ? (a) : (b))
#define MAX3(a, b, c) MAX2(MAX2(a, b), c)

#define PROV_IDENTIFIER_BUFFER_LENGTH MAX3(sizeof(struct node_identifier), sizeof(struct relation_identifier), sizeof(struct packet_identifier))

union prov_identifier
{
    struct node_identifier node_id;
    struct relation_identifier relation_id;
    struct packet_identifier packet_id;
    uint8_t buffer[PROV_IDENTIFIER_BUFFER_LENGTH];
};

struct msg_struct
{
    union prov_identifier identifier;
    uint32_t internal_flag; // 标志着节点是否重复记录
};

struct relation_struct
{
    union prov_identifier identifier;
    uint8_t allowed;
    union prov_identifier snd;
    union prov_identifier rcv;
    uint8_t set;
    int64_t offset;
    uint64_t flags;
    uint32_t cap;
    uint64_t syscall_nid;
};

#define shared_node_elements \
    uint64_t previous_id;    \
    uint64_t previous_type;  \
    uint32_t k_version;      \
    uint32_t secid;          \
    uint32_t uid;            \
    uint32_t gid;            \
    void *var_ptr

struct node_struct
{
    union prov_identifier identifier;
    shared_node_elements;
};

// #define _KERNEL_CAPABILITY_U32S  2
struct task_prov_struct
{
    union prov_identifier identifier;
    shared_node_elements;
    uint32_t tid;  //线程号
    uint32_t pid;  //领头线程号，即进程号
    char comm[MAX_STRING_SIZE];
    char cwd[MAX_STRING_SIZE];
    /* KB */
    uint32_t utsns;
    uint32_t ipcns;
    uint32_t mntns;
    uint32_t pidns;
    uint32_t netns;
    uint32_t cgroupns;
    uint32_t userns;
    uint32_t cap_effective[2];    // CapEff
};

#define PROV_SBUUID_LEN 16
struct inode_prov_struct {
	union prov_identifier identifier;
	shared_node_elements;
	uint64_t ino;
	uint16_t mode;
    uint8_t sb_uuid[PROV_SBUUID_LEN];
};

struct proc_prov_struct {
	union prov_identifier identifier;
	shared_node_elements;
    uint32_t tid;  //线程号
    uint32_t pid;  //领头线程号，即进程号
    char comm[MAX_STRING_SIZE];
    uint32_t userns;
    uint32_t cap_effective[2];    // CapEff
};

typedef __SIZE_TYPE__ size_t; /* sizeof() */
struct file_name_struct
{
    union prov_identifier identifier;
    shared_node_elements;
    char name[200];
    size_t length;
    int overlay_flag;
    char host_path[10];
    char mount_path[20];
};

struct msg_msg_struct {
	union prov_identifier identifier;
	shared_node_elements;
	long type;
};

union prov_elt
{
    struct msg_struct msg_info;
    struct relation_struct relation_info;
    struct node_struct node_info;
    struct task_prov_struct task_info;
    struct inode_prov_struct inode_info;
    struct proc_prov_struct proc_info;
    struct msg_msg_struct msg_msg_info;
};

struct address_struct {
	union prov_identifier identifier;
	shared_node_elements;
	uint8_t addr[MAX_STRING_SIZE*2];
	size_t length;
};

union long_prov_elt
{
    struct relation_struct relation_info;
    struct node_struct node_info;
    struct task_prov_struct task_info;
    struct file_name_struct file_name_info;
    struct inode_prov_struct inode_info;
    struct address_struct address_info;
};

typedef union long_prov_elt prov_entry_t;

#define prov_flag(prov) ((prov)->msg_info.internal_flag)

#define prov_set_flag(node, nbit) (prov_flag(node) |= 1 << nbit)
#define prov_clear_flag(node, nbit) (prov_flag(node) &= ~(1 << nbit))
#define prov_check_flag(node, nbit) ((prov_flag(node) & (1 << nbit)) == (1 << nbit))

#define NAMED_BIT           2
#define set_named(node)                     prov_set_flag(node, NAMED_BIT)
#define clear_named(node)                   prov_clear_flag(node, NAMED_BIT)
#define provenance_is_named(node)           prov_check_flag(node, NAMED_BIT)

#define OUTGOING_BIT 4
#define set_has_outgoing(node) prov_set_flag(node, OUTGOING_BIT)
#define clear_has_outgoing(node) prov_clear_flag(node, OUTGOING_BIT)
#define provenance_has_outgoing(node) prov_check_flag(node, OUTGOING_BIT)

#define INITIALIZED_BIT 5
#define set_initialized(node) prov_set_flag(node, INITIALIZED_BIT)
#define clear_initialized(node) prov_clear_flag(node, INITIALIZED_BIT)
#define provenance_is_initialized(node) prov_check_flag(node, INITIALIZED_BIT)

#define RECORDED_BIT 7
#define set_prov_recorded(node) prov_set_flag(node, RECORDED_BIT)
#define clear_prov_recorded(node) prov_clear_flag(node, RECORDED_BIT)
#define provenance_is_recorded(node) prov_check_flag(node, RECORDED_BIT)

#define node_identifier(node) ((node)->node_info.identifier.node_id)

#define node_previous_id(node) ((node)->node_info.previous_id)
#define node_previous_type(node) ((node)->node_info.previous_type)

#define relation_identifier(relation) ((relation)->relation_info.identifier.relation_id)

#endif