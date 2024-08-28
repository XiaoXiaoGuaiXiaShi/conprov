#include "kern/vmlinux.h"

#include <linux/libc-compat.h>
#include <linux/mman.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <linux/limits.h>

#include "shared/common.h"
#include "shared/prov_struct.h"
#include "kern/task.h"
#include "kern/maps.h"
#include "kern/record.h"
#include "kern/inode.h"
#include "kern/net.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int key_count = 0;
int array_key = 0;
unsigned int inum = 0;

int task_tid=0;
int task_cap=1000;
long task_syscall=1000;

int openat_flag=0;

char host_path[TASK_COMM_LEN]="";
char mount_path[TASK_COMM_LEN]="";

static int get_pid(struct task_struct *current_task)
{
	pid_t pid = bpf_core_field_exists(current_task->pid) ? BPF_CORE_READ(current_task, pid) : -1;
	// v2
	// unsigned int task_inum = bpf_core_field_exists(current_task->nsproxy->cgroup_ns->ns.inum) ? BPF_CORE_READ(current_task, nsproxy, cgroup_ns, ns.inum) : -1;
	// v1
	unsigned int task_inum = bpf_core_field_exists(current_task->cgroups->subsys[4]->cgroup->kn->id) ? BPF_CORE_READ(current_task, cgroups, subsys[4], cgroup, kn, id) : -1;
	struct process_event *proc;
	proc = bpf_map_lookup_elem(&processes, &pid);
    if (proc)
	{
		inum = task_inum;
		// bpf_printk("inum, container's pid: %d.\n", pid);
		return 1;
	}
	if (inum != 0 && inum == task_inum)
	{
		// bpf_printk("current_task->nsproxy->cgroup_ns->ns.inum: %x.\n", inum);
		return 1;
	}
	return 0;
}

static int strlen(char *str)
{
	int i;
	#pragma clang loop unroll(full)
	for(i=0;i<10;i++){
		if(str[i]=='\0'|| str[i]==NULL)
			break;
	}
	return i;
}

static int strcat(char *s1, char *s2, int s1_len, char *result)
{
	int i;
	bpf_probe_read_str(result, MAX_STRING_SIZE, s1);
	char * _result = &result[s1_len];
	bpf_probe_read_str(_result, MAX_STRING_SIZE-s1_len, s2);
	return 0;
}

static int strcmp(char *s1, char *s2, int s_len)
{
	int i;
	int flag=1;
	#pragma clang loop unroll(full)
	for(i=0;i<s_len;i++){
		if(s1[i]!=s2[i])
			flag = 0;
			break;
	}
	return flag;
}

static union long_prov_elt* get_file_path_prov(struct file *file, int f_type) {
    int map_id = PATH_PERCPU_LONG_TMP;
    union long_prov_elt *pprov;
	pprov = bpf_map_lookup_elem(&long_tmp_prov_map, &map_id);
	char slash[1];
	slash[0]='/';
	char tmp[MAX_STRING_SIZE]="";
	int s_len = 1;
    if (pprov)
	{
    	prov_init_node((union prov_elt *)pprov, ENT_PATH);
		// proc file
		if(f_type==1)
		{
			strcpy(tmp, "/proc/");
			s_len = 6;
			char *name = (char *) BPF_CORE_READ(file, f_path.dentry, d_parent, d_parent, d_name.name);
			char name_flag[2];
			bpf_probe_read_str(&name_flag, 2, name);
			if(name_flag[0] != '/')
			{
				strcat(tmp, name, s_len, tmp);
				s_len = strlen(tmp);
				strcat(tmp, slash, s_len, tmp);
				s_len += 1;
				// bpf_printk("parent.parent,name_flag:%c!\n", name_flag[1]);
			}
			name = (char *) BPF_CORE_READ(file, f_path.dentry, d_parent, d_name.name);
			bpf_probe_read_str(&name_flag, 2, name);
			if(name_flag[0] != '/')
			{
				strcat(tmp, name, s_len, tmp);
				s_len = strlen(tmp);
				strcat(tmp, slash, s_len, tmp);
				s_len += 1;
			}
			name = (char *) BPF_CORE_READ(file, f_path.dentry, d_name.name);
			strcat(tmp, name, s_len, &(pprov->file_name_info.name));
			pprov->file_name_info.overlay_flag=4;
		}
		else if (f_type==2) //sys file
		{
			strcpy(tmp, "/sys/");
			s_len = 5;
			char *name = (char *) BPF_CORE_READ(file, f_path.dentry, d_parent, d_parent, d_name.name);
			char name_flag[2];
			bpf_probe_read_str(&name_flag, 2, name);
			if(name_flag[0] != '/')
			{
				strcat(tmp, name, s_len, tmp);
				s_len = strlen(tmp);
				strcat(tmp, slash, s_len, tmp);
				s_len += 1;
			}
			name = (char *) BPF_CORE_READ(file, f_path.dentry, d_parent, d_name.name);
			bpf_probe_read_str(&name_flag, 2, name);
			if(name_flag[0] != '/')
			{
				strcat(tmp, name, s_len, tmp);
				s_len = strlen(tmp);
				strcat(tmp, slash, s_len, tmp);
				s_len += 1;
				// bpf_printk("parent,name_flag:%c!\n", name_flag[1]);
				// bpf_printk("parent,name:%s!\n", name);
			}
			name = (char *) BPF_CORE_READ(file, f_path.dentry, d_name.name);
			strcat(tmp, name, s_len, &(pprov->file_name_info.name));
			// bpf_printk("file->f_path.dentry->d_name.name:%s.\n", pprov->file_name_info.name);
			pprov->file_name_info.overlay_flag=3;
		}
		else if (f_type==4) //cgroup file
		{
			strcpy(tmp, "/");
			// just three
			char *name = (char *) BPF_CORE_READ(file, f_path.dentry, d_parent, d_parent, d_name.name);
			char name_flag[2];
			bpf_probe_read_str(&name_flag, 2, name);
			if(name_flag[0] != '/')
			{
				strcat(slash, name, s_len, tmp);
				s_len = strlen(tmp);
				strcat(tmp, slash, s_len, tmp);
				s_len += 1;
			}
			name = (char *) BPF_CORE_READ(file, f_path.dentry, d_parent, d_name.name);
			bpf_probe_read_str(&name_flag, 2, name);
			if(name_flag[0] != '/')
			{
				strcat(tmp, name, s_len, tmp);
				s_len = strlen(tmp);
				strcat(tmp, slash, s_len, tmp);
				s_len += 1;
			}
			pprov->file_name_info.overlay_flag=7;
			name = (char *) BPF_CORE_READ(file, f_path.dentry, d_name.name);
			strcat(tmp, name, s_len, &(pprov->file_name_info.name));
			// bpf_printk("file->f_path.dentry->d_name.name:%s.\n", pprov->file_name_info.name);
		}
		else  // other files
		{
			strcpy(tmp, "/");
			// 只做了三次展开
			char *name = (char *) BPF_CORE_READ(file, f_path.dentry, d_parent, d_parent, d_name.name);
			char name_flag[2];
			bpf_probe_read_str(&name_flag, 2, name);
			if(name_flag[0] != '/')
			{
				strcat(slash, name, s_len, tmp);
				s_len = strlen(tmp);
				strcat(tmp, slash, s_len, tmp);
				s_len += 1;
			}
			name = (char *) BPF_CORE_READ(file, f_path.dentry, d_parent, d_name.name);
			bpf_probe_read_str(&name_flag, 2, name);
			if(name_flag[0] != '/')
			{
				strcat(tmp, name, s_len, tmp);
				s_len = strlen(tmp);
				strcat(tmp, slash, s_len, tmp);
				s_len += 1;
			}
			name = (char *) BPF_CORE_READ(file, f_path.dentry, d_name.name);
			strcat(tmp, name, s_len, &(pprov->file_name_info.name));

			if(f_type==3)
			{
				pprov->file_name_info.overlay_flag=6;
			}
		}
		strcpy(tmp, "");
		// bpf_printk("pprov->file_name_info.name:%s.\n", pprov->file_name_info.name);
	}
    return pprov;
}

static void prov_init_inode(struct file *file, union prov_elt *prov) {
    int index;
	uint8_t *sb_uuid= (uint8_t *) BPF_CORE_READ(file, f_inode, i_sb, s_uuid.b);
	bpf_probe_read_str(&(prov->inode_info.sb_uuid), PROV_SBUUID_LEN, sb_uuid);

    prov->inode_info.secid = 0;
    prov->inode_info.mode = bpf_core_field_exists(file->f_inode->i_mode) ? BPF_CORE_READ(file, f_inode, i_mode) : -1;
    prov->inode_info.ino = bpf_core_field_exists(file->f_inode->i_ino) ? BPF_CORE_READ(file, f_inode, i_ino) : -1;
}

// security_task_alloc:fork()
SEC("kprobe/security_task_alloc")
int BPF_KPROBE(security_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	union prov_elt *tprov;

	if (!get_pid(current_task))
		return 0;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;
	
	int c_map_id = TASK_PERCPU_TMP;
	union prov_elt *tnprov = bpf_map_lookup_elem(&cp_task_map, &c_map_id);
	if (!tnprov)
		return 0;
	if (!__set_initalized(tnprov)) {
        prov_init_node(tnprov, ENT_PROC);
    }
	char *comm = (char *) BPF_CORE_READ(task, comm);
	bpf_probe_read_str(&(tnprov->proc_info.comm), MAX_STRING_SIZE, comm);

	tnprov->proc_info.pid = bpf_core_field_exists(task->tgid) ? BPF_CORE_READ(task, tgid) : -1;
	tnprov->proc_info.tid = bpf_core_field_exists(task->pid) ? BPF_CORE_READ(task, pid) : -1;
	tnprov->proc_info.userns = bpf_core_field_exists(task->real_cred->user_ns->ns.inum) ? BPF_CORE_READ(task, real_cred, user_ns, ns.inum) : -1;

	tnprov->proc_info.cap_effective[0] = bpf_core_field_exists(task->real_cred->cap_effective.cap[0]) ? BPF_CORE_READ(task, real_cred, cap_effective.cap[0]) : -1;
	tnprov->proc_info.cap_effective[1] = bpf_core_field_exists(task->real_cred->cap_effective.cap[1]) ? BPF_CORE_READ(task, real_cred, cap_effective.cap[1]) : -1;
	
	
	informs(RL_CLONE, tprov, tnprov, NULL, 1000, clone_flags);
	return 0;
}

SEC("kprobe/security_task_free")
int BPF_KPROBE(security_task_free, struct task_struct *task)
{
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	union prov_elt *tprov;

	if (!get_pid(current_task))
		return 0;
	tprov = get_task_prov(current_task);
	if(!tprov)
		return 0;
	/* Record task terminate */
	record_terminate(RL_TERMINATE_TASK, tprov);
	return 0;
}

// tracepoint:syscalls:sys_enter_execve:execve()
SEC("tp/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	union prov_elt *tprov;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;

    // char * filename = (char *)ctx->args[0];
	// bpf_printk("filename: %s.\n", filename);

	return 0;
}

// tracepoint:syscalls:sys_enter_mount
SEC("tp/syscalls/sys_enter_mount")
int tp_mount(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	union prov_elt *tprov;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;

	char *dev_name = (char *)ctx->args[0];
	// bpf_printk("dev_name:%s.\n", dev_name);
	char *dir_name = (char *)ctx->args[1];
	// bpf_printk("dir_name:%s.\n", dir_name);

	bpf_probe_read_str(&host_path, TASK_COMM_LEN, dev_name);
	bpf_probe_read_str(&mount_path, TASK_COMM_LEN, dir_name);
	
	return 0;
}

// tracepoint:syscalls:sys_enter_openat:openat()
SEC("tp/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
	if(!openat_flag)
		return 0;
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	union prov_elt *tprov;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;

	char *filename = (char *)ctx->args[1];
	uint64_t type = ENT_INODE_FILE;
	// bpf_printk("filename:%s.\n", filename);

	int c_map_id = TASK_PERCPU_TMP;
	union prov_elt *iprov = bpf_map_lookup_elem(&cp_task_map, &c_map_id);
	if(!iprov)
		return 0;
	// if (!__set_initalized(iprov)) {
	// 	prov_init_node(iprov, type);
	// }
	prov_init_node(iprov, type);
		
	if (!__set_name(iprov)) {
        union long_prov_elt *pprov;
		int map_id = PATH_PERCPU_LONG_TMP;
		pprov = bpf_map_lookup_elem(&long_tmp_prov_map, &map_id);
		if (pprov)
		{
			prov_init_node((union prov_elt *)pprov, ENT_PATH);
			bpf_probe_read_str(&(pprov->file_name_info.name), MAX_STRING_SIZE, filename);
		}
        if(!pprov)
            return 0;

		int mount_len = strlen(mount_path);
		int cmp_flag = strcmp(&(pprov->file_name_info.name), mount_path, 3);
		// bpf_printk("cmp_flag:%d.\n", cmp_flag);
		if(cmp_flag)
		{
			pprov->file_name_info.overlay_flag=9;
			bpf_probe_read_str(&(pprov->file_name_info.host_path), TASK_COMM_LEN, host_path);
			bpf_probe_read_str(&(pprov->file_name_info.mount_path), TASK_COMM_LEN, mount_path);
		}
		// bpf_printk("host_path:%s.\n", &(pprov->file_name_info.host_path));
		// bpf_printk("mount_path:%s.\n", &(pprov->file_name_info.mount_path));
        __record_relation_ls(RL_NAMED, pprov, iprov, NULL, 0);
    }
	
	__record_relation(RL_OPEN, iprov, tprov, NULL, 1000, 0, 257);
	
	openat_flag = 0;
	return 0;
}

SEC("kprobe/security_file_permission")
int BPF_KPROBE(security_file_permission, struct file *file, int mask) 
{
	u64 start_time_ns = bpf_ktime_get_ns();

	union prov_elt *tprov;
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;
	
	int c_map_id = TASK_PERCPU_TMP;
	union prov_elt *iprov = bpf_map_lookup_elem(&tmp_prov_elt_map, &c_map_id);
	if(!iprov)
		return 0;
	umode_t imode = bpf_core_field_exists(file->f_inode->i_mode) ? BPF_CORE_READ(file, f_inode, i_mode) : -1;
	if (!__set_initalized(iprov)) {
		uint64_t type;
		if (S_ISREG(imode)) {
            // inode mode is regular file
            type = ENT_INODE_FILE;
        } else if (S_ISDIR(imode)) {
            // inode mode is directory
            type = ENT_INODE_DIRECTORY;
        } else if (S_ISCHR(imode)) {
            // inode mode is character device
            type = ENT_INODE_CHAR;
        } else if (S_ISBLK(imode)) {
            // inode mode is block device
            type = ENT_INODE_BLOCK;
        } else if (S_ISFIFO(imode)) {
            // inode mode is FIFO (named pipe)
            type = ENT_INODE_PIPE;
        } else if (S_ISLNK(imode)) {
            // inode mode is symbolic link
            type = ENT_INODE_LINK;
        } else if (S_ISSOCK(imode)) {
            // inode mode is socket
            type = ENT_INODE_SOCKET;
        } else {
            // inode mode is unknown
            type = ENT_INODE_UNKNOWN;
        }
		prov_init_node(iprov, type);
        prov_init_inode(file, iprov);
	}
	iprov->inode_info.uid = bpf_core_field_exists(file->f_inode->i_uid.val) ? BPF_CORE_READ(file, f_inode, i_uid.val) : -1;
    iprov->inode_info.gid = bpf_core_field_exists(file->f_inode->i_gid.val) ? BPF_CORE_READ(file, f_inode, i_gid.val) : -1;
	if (!__set_name(iprov) && S_ISREG(imode)) {
        union long_prov_elt *pprov;
		char *file_type = (char *) BPF_CORE_READ(file, f_inode, i_sb, s_type, name);
		char proc_type[5]="proc";
		char sys_type[5]="sys";
		char lay_type[8]="overlay";
		char cgroup_type[7]="cgroup";
		int f_type=0;

		char s1[10];
		bpf_probe_read_str(s1, 10, file_type);
		// bpf_printk("file_type:%s.\n",file_type);

		if(strcmp(s1, proc_type, 4))
		{
			f_type=1;
			// bpf_printk("proc:%s.\n", pprov->file_name_info.name);
		}
		if(strcmp(s1, sys_type, 3))
		{
			f_type=2;
			// bpf_printk("sys:%s.\n", pprov->file_name_info.name);
		}
		if(strcmp(s1, lay_type, 6))
		{
			f_type=3;
			// bpf_printk("sys:%s.\n", pprov->file_name_info.name);
		}
		if(strcmp(s1, cgroup_type, 6))
		{
			f_type=4;
			// bpf_printk("cgroup_type:%s.\n", pprov->file_name_info.name);
		}
		pprov = get_file_path_prov(file, f_type);
        if(!pprov)
            return 0;
        __record_relation_ls(RL_NAMED, pprov, iprov, NULL, 0);
    }

	if (!iprov)
      return 0;
	  
	uint32_t perms= 0;
	if (!S_ISDIR(imode)) {
		if (mask & MAY_EXEC)
			perms |= FILE__EXECUTE;
		if (mask & MAY_READ)
			perms |= FILE__READ;
		if (mask & MAY_APPEND)
			perms |= FILE__APPEND;
		else if (mask & MAY_WRITE)
			perms |= FILE__WRITE;
	} else {
		if (mask & MAY_EXEC)
			perms |= DIR__SEARCH;
		if (mask & MAY_WRITE)
			perms |= DIR__WRITE;
		if (mask & MAY_READ)
			perms |= DIR__READ;
	}
	
    if (S_ISSOCK(imode)) {
        if ((perms & (FILE__WRITE | FILE__APPEND)) != 0)
			__record_relation(RL_SND, tprov, iprov, file, 1000, mask, 1000);
        if ((perms & (FILE__READ)) != 0)
			__record_relation(RL_RCV, iprov, tprov, file, 1000, mask, 1000);
    } else {
        if ((perms & (FILE__WRITE | FILE__APPEND)) != 0)
			__record_relation(RL_WRITE, tprov, iprov, file, 1000, mask, 1000);
        if ((perms & (FILE__READ)) != 0)
		{
			if(current_task->pid==task_tid && task_cap!=1000)
			{
				__record_relation(RL_READ, iprov, tprov, file, task_cap, mask, task_syscall);
				// bpf_printk("task_cap %d; task_tid: %d; task_syscall: %ld\n", task_cap, task_tid, task_syscall);
				task_cap=1000;
				task_tid=0;
				task_syscall=1000;
			}
			else
			{
				__record_relation(RL_READ, iprov, tprov, file, 1000, mask, 1000);
			}
		}
			
        if ((perms & (FILE__EXECUTE)) != 0) {
            derives(RL_EXEC, iprov, tprov, file, mask);
        }
    }

	u64 end_time_ns = bpf_ktime_get_ns();
	u64 execution_time_ns = end_time_ns-start_time_ns;
	bpf_printk("Execution time: %llu ns.\n", execution_time_ns);

    return 0;	
}

SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(security_file_ioctl, struct file *file, unsigned int cmd, long unsigned int arg) 
{
	union prov_elt *tprov;
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;

	int c_map_id = TASK_PERCPU_TMP;
	union prov_elt *iprov = bpf_map_lookup_elem(&tmp_prov_elt_map, &c_map_id);
	if(!iprov)
		return 0;
	umode_t imode = bpf_core_field_exists(file->f_inode->i_mode) ? BPF_CORE_READ(file, f_inode, i_mode) : -1;
	if (!__set_initalized(iprov)) {
		uint64_t type;
		if (S_ISREG(imode)) {
            // inode mode is regular file
            type = ENT_INODE_FILE;
        } else if (S_ISDIR(imode)) {
            // inode mode is directory
            type = ENT_INODE_DIRECTORY;
        } else if (S_ISCHR(imode)) {
            // inode mode is character device
            type = ENT_INODE_CHAR;
        } else if (S_ISBLK(imode)) {
            // inode mode is block device
            type = ENT_INODE_BLOCK;
        } else if (S_ISFIFO(imode)) {
            // inode mode is FIFO (named pipe)
            type = ENT_INODE_PIPE;
        } else if (S_ISLNK(imode)) {
            // inode mode is symbolic link
            type = ENT_INODE_LINK;
        } else if (S_ISSOCK(imode)) {
            // inode mode is socket
            type = ENT_INODE_SOCKET;
        } else {
            // inode mode is unknown
            type = ENT_INODE_UNKNOWN;
        }
		prov_init_node(iprov, type);
        prov_init_inode(file, iprov);
	}
	iprov->inode_info.uid = bpf_core_field_exists(file->f_inode->i_uid.val) ? BPF_CORE_READ(file, f_inode, i_uid.val) : -1;
    iprov->inode_info.gid = bpf_core_field_exists(file->f_inode->i_gid.val) ? BPF_CORE_READ(file, f_inode, i_gid.val) : -1;
	if (!__set_name(iprov) && S_ISREG(imode)) {
        union long_prov_elt *pprov;
		char *file_type = (char *) BPF_CORE_READ(file, f_inode, i_sb, s_type, name);
		char proc_type[5]="proc";
		char sys_type[5]="sys";
		char lay_type[8]="overlay";
		char cgroup_type[7]="cgroup";
		int f_type=0;

		char s1[10];
		bpf_probe_read_str(s1, 10, file_type);
		// bpf_printk("file_type:%s.\n",file_type);

		if(strcmp(s1, proc_type, 4))
		{
			f_type=1;
			// bpf_printk("proc:%s.\n", pprov->file_name_info.name);
		}
		if(strcmp(s1, sys_type, 3))
		{
			f_type=2;
			// bpf_printk("sys:%s.\n", pprov->file_name_info.name);
		}
		if(strcmp(s1, lay_type, 6))
		{
			f_type=3;
			// bpf_printk("sys:%s.\n", pprov->file_name_info.name);
		}
		if(strcmp(s1, cgroup_type, 6))
		{
			f_type=4;
			// bpf_printk("cgroup_type:%s.\n", pprov->file_name_info.name);
		}
		pprov = get_file_path_prov(file, f_type);
        if(!pprov)
            return 0;
        __record_relation_ls(RL_NAMED, pprov, iprov, NULL, 0);
    }
	
	if (!iprov)
      return 0;
	
	__record_relation(RL_WRITE_IOCTL, tprov, iprov, file, 1000, cmd, 1000);
	__record_relation(RL_READ_IOCTL, iprov, tprov, file, 1000, cmd, 1000);

	return 0;
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(security_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) 
{
	// int real_pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	union prov_elt *tprov;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;
		
	int c_map_id = TASK_PERCPU_TMP;
	union prov_elt *cprov = bpf_map_lookup_elem(&cp_task_map, &c_map_id);
	if (!cprov)
		return 0;
	if (!__set_initalized(cprov)) {
        prov_init_node(cprov, ENT_PROC);
    }
	char *comm = (char *) BPF_CORE_READ(current_task, comm);
	bpf_probe_read_str(&(cprov->proc_info.comm), MAX_STRING_SIZE, comm);

	cprov->proc_info.pid = bpf_core_field_exists(current_task->tgid) ? BPF_CORE_READ(current_task, tgid) : -1;
	cprov->proc_info.tid = bpf_core_field_exists(current_task->pid) ? BPF_CORE_READ(current_task, pid) : -1;
	cprov->proc_info.userns = bpf_core_field_exists(current_task->real_cred->user_ns->ns.inum) ? BPF_CORE_READ(current_task, real_cred, user_ns, ns.inum) : -1;
	
	cprov->proc_info.cap_effective[0] = bpf_core_field_exists(current_task->real_cred->cap_effective.cap[0]) ? BPF_CORE_READ(current_task, real_cred, cap_effective.cap[0]) : -1;
	cprov->proc_info.cap_effective[1] = bpf_core_field_exists(current_task->real_cred->cap_effective.cap[1]) ? BPF_CORE_READ(current_task, real_cred, cap_effective.cap[1]) : -1;
	
	union prov_elt *iprov = bpf_map_lookup_elem(&tmp_prov_elt_map, &c_map_id);
	if (!iprov)
		return 0;

    umode_t i_mode = bpf_core_field_exists(sock->file->f_inode->i_mode) ? BPF_CORE_READ(sock, file, f_inode, i_mode) : -1;
	if (S_ISDIR(i_mode))
        return 0;
	
	if (!__set_initalized(iprov))
	{
        prov_init_node(iprov, ENT_INODE_SOCKET);
		iprov->inode_info.secid = 0;
		iprov->inode_info.mode = i_mode;
		iprov->inode_info.ino = bpf_core_field_exists(sock->file->f_inode->i_ino) ? BPF_CORE_READ(sock, file, f_inode, i_ino) : -1;
	}

	iprov->inode_info.uid = bpf_core_field_exists(sock->file->f_inode->i_uid.val) ? BPF_CORE_READ(sock, file, f_inode, i_uid.val) : -1;
    iprov->inode_info.gid = bpf_core_field_exists(sock->file->f_inode->i_gid.val) ? BPF_CORE_READ(sock, file, f_inode, i_gid.val) : -1;

    record_address(address, addrlen, iprov);
    generates(RL_CONNECT, current_task, cprov, tprov, iprov, NULL, 0);
    return 0;
}

SEC("kprobe/bpf_lsm_msg_msg_alloc_security")
int BPF_KPROBE(bpf_lsm_msg_msg_alloc_security, struct msg_msg *msg) {
	// int real_pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	union prov_elt *tprov;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;
	
	int c_map_id = TASK_PERCPU_TMP;
	union prov_elt *cprov = bpf_map_lookup_elem(&cp_task_map, &c_map_id);
	if (!cprov)
		return 0;
	
	if (!__set_initalized(cprov)) {
        prov_init_node(cprov, ENT_PROC);
    }
	char *comm = (char *) BPF_CORE_READ(current_task, comm);
	bpf_probe_read_str(&(cprov->proc_info.comm), MAX_STRING_SIZE, comm);

	cprov->proc_info.pid = bpf_core_field_exists(current_task->tgid) ? BPF_CORE_READ(current_task, tgid) : -1;
	cprov->proc_info.tid = bpf_core_field_exists(current_task->pid) ? BPF_CORE_READ(current_task, pid) : -1;
	cprov->proc_info.userns = bpf_core_field_exists(current_task->real_cred->user_ns->ns.inum) ? BPF_CORE_READ(current_task, real_cred, user_ns, ns.inum) : -1;
	
	cprov->proc_info.cap_effective[0] = bpf_core_field_exists(current_task->real_cred->cap_effective.cap[0]) ? BPF_CORE_READ(current_task, real_cred, cap_effective.cap[0]) : -1;
	cprov->proc_info.cap_effective[1] = bpf_core_field_exists(current_task->real_cred->cap_effective.cap[1]) ? BPF_CORE_READ(current_task, real_cred, cap_effective.cap[1]) : -1;

	union prov_elt *mprov = bpf_map_lookup_elem(&tmp_prov_elt_map, &c_map_id);
	if (!mprov)
		return 0;

	if (!__set_initalized(mprov))
	{
        prov_init_node(mprov, ENT_MSG);
		mprov->msg_msg_info.type = bpf_core_field_exists(msg->m_type) ? BPF_CORE_READ(msg, m_type) : -1;
	}

    generates(RL_MSG_CREATE, current_task, cprov, tprov, mprov, NULL, 0);
    return 0;
}

SEC("kprobe/bpf_lsm_msg_msg_free_security")
int BPF_KPROBE(bpf_lsm_msg_msg_free_security, struct msg_msg *msg) {
	// int real_pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	union prov_elt *tprov;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;

	int map_id = TASK_PERCPU_TMP;
	union prov_elt *mprov = bpf_map_lookup_elem(&tmp_prov_elt_map, &map_id);
	if (!mprov)
		return 0;

	if (!__set_initalized(mprov))
	{
        prov_init_node(mprov, ENT_MSG);
		mprov->msg_msg_info.type = bpf_core_field_exists(msg->m_type) ? BPF_CORE_READ(msg, m_type) : -1;
	}

    record_terminate(RL_FREED, mprov);
    return 0;
}

SEC("kprobe/security_capable")
int BPF_KPROBE(security_capable, const struct cred *cred, struct user_namespace *targ_ns, int cap, unsigned int opts)
{
	// int real_pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	union prov_elt *tprov;
	tprov = get_task_prov(current_task);
	if (!tprov)
		return 0;
	
	// bpf_printk("cap %d\n", cap);
	// int default_cap[14]={0,1,3,4,5,6,7,8,10,13,18,27,29,31};
	// int i;
	// #pragma clang loop unroll(full)
	// for(i=0;i<14;i++){
	// 	if(cap==default_cap[i])
	// 		return 0;
	// }

	task_cap = cap;
	task_tid = current_task->pid;

	int map_id = TASK_PERCPU_TMP;
	union prov_elt *iprov = bpf_map_lookup_elem(&cp_task_map, &map_id);
	if (!iprov)
		return 0;

	if (!__set_initalized(iprov)) {
        prov_init_node(iprov, ENT_PROC);
    }
	char *comm = (char *) BPF_CORE_READ(current_task, comm);
	bpf_probe_read_str(&(iprov->proc_info.comm), MAX_STRING_SIZE, comm);

	iprov->proc_info.pid = bpf_core_field_exists(current_task->tgid) ? BPF_CORE_READ(current_task, tgid) : -1;
	iprov->proc_info.tid = bpf_core_field_exists(current_task->pid) ? BPF_CORE_READ(current_task, pid) : -1;
	iprov->proc_info.userns = bpf_core_field_exists(cred->user_ns->ns.inum) ? BPF_CORE_READ(cred, user_ns, ns.inum) : -1;

	iprov->proc_info.cap_effective[0] = bpf_core_field_exists(cred->cap_effective.cap[0]) ? BPF_CORE_READ(cred, cap_effective.cap[0]) : -1;
	iprov->proc_info.cap_effective[1] = bpf_core_field_exists(cred->cap_effective.cap[1]) ? BPF_CORE_READ(cred, cap_effective.cap[1]) : -1;

	informs(RL_CLONE, tprov, iprov, NULL, cap, 0);
	// if(current_task->pid==task_tid && task_cap!=1000)
	// {
	// 	__record_relation(RL_CLONE, tprov, iprov, NULL, task_cap, 0, task_syscall);
	// 	// bpf_printk("task_cap %d; task_tid: %d; task_syscall: %ld\n", task_cap, task_tid, task_syscall);
	// 	task_cap=1000;
	// 	task_tid=0;
	// 	task_syscall=1000;
	// }
	// else
	// {
	// 	informs(RL_CLONE, tprov, iprov, NULL, cap, 0);
	// }

	return 0;
}

SEC("kprobe/security_capset")
int BPF_KPROBE(security_capset, struct cred * new, const struct cred * old, const kernel_cap_t * effective, const kernel_cap_t * inheritable, const kernel_cap_t * permitted)
{
	// int real_pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;
	
	int map_id = TASK_PERCPU_TMP;
	union prov_elt *tprov = bpf_map_lookup_elem(&tmp_prov_elt_map, &map_id);
	if (!tprov)
		return 0;

	if (!__set_initalized(tprov)) {
        prov_init_node(tprov, ENT_PROC);
    }
	char *comm = (char *) BPF_CORE_READ(current_task, comm);
	bpf_probe_read_str(&(tprov->proc_info.comm), MAX_STRING_SIZE, comm);

	tprov->proc_info.pid = bpf_core_field_exists(current_task->tgid) ? BPF_CORE_READ(current_task, tgid) : -1;
	tprov->proc_info.tid = bpf_core_field_exists(current_task->pid) ? BPF_CORE_READ(current_task, pid) : -1;
	tprov->proc_info.userns = bpf_core_field_exists(old->user_ns->ns.inum) ? BPF_CORE_READ(old, user_ns, ns.inum) : -1;

	tprov->proc_info.cap_effective[0] = bpf_core_field_exists(old->cap_effective.cap[0]) ? BPF_CORE_READ(old, cap_effective.cap[0]) : -1;
	tprov->proc_info.cap_effective[1] = bpf_core_field_exists(old->cap_effective.cap[1]) ? BPF_CORE_READ(old, cap_effective.cap[1]) : -1;

	union prov_elt *iprov = bpf_map_lookup_elem(&cp_task_map, &map_id);
	if (!iprov)
		return 0;

	if (!__set_initalized(iprov)) {
        prov_init_node(iprov, ENT_PROC);
    }

	bpf_probe_read_str(&(iprov->proc_info.comm), MAX_STRING_SIZE, comm);

	iprov->proc_info.pid = bpf_core_field_exists(current_task->tgid) ? BPF_CORE_READ(current_task, tgid) : -1;
	iprov->proc_info.tid = bpf_core_field_exists(current_task->pid) ? BPF_CORE_READ(current_task, pid) : -1;
	iprov->proc_info.userns = bpf_core_field_exists(new->user_ns->ns.inum) ? BPF_CORE_READ(new, user_ns, ns.inum) : -1;

	iprov->proc_info.cap_effective[0] = bpf_core_field_exists(new->cap_effective.cap[0]) ? BPF_CORE_READ(new, cap_effective.cap[0]) : -1;
	iprov->proc_info.cap_effective[1] = bpf_core_field_exists(new->cap_effective.cap[1]) ? BPF_CORE_READ(new, cap_effective.cap[1]) : -1;

	informs(RL_CLONE, tprov, iprov, NULL, 1000, 0);
	// if(current_task->pid==task_tid && task_cap!=1000)
	// {
	// 	__record_relation(RL_CLONE, tprov, iprov, NULL, task_cap, 0, task_syscall);
	// 	// bpf_printk("task_cap %d; task_tid: %d; task_syscall: %ld\n", task_cap, task_tid, task_syscall);
	// 	task_cap=1000;
	// 	task_tid=0;
	// 	task_syscall=1000;
	// }
	// else
	// {
	// 	informs(RL_CLONE, tprov, iprov, NULL, 1000, 0);
	// }

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *args) {
	struct task_struct *current_task = (struct task_struct *)bpf_get_current_task_btf();
	if (!get_pid(current_task))
		return 0;

	long syscall_id=args->id;
	if(current_task->pid==task_tid && task_cap!=1000)
	{
		task_syscall = syscall_id;
	}
	if(syscall_id==257)
	{
		openat_flag = 1;
		// bpf_printk("NR %ld\n", syscall_id);
	}	
    
    return 0;
}
