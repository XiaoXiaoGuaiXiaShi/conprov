#ifndef _COMMON_H
#define _COMMON_H

#define TASK_COMM_LEN 16
#define MAX_CONTAINER_LEN 200
#define MAX_CMD_LEN 128

struct process_event
{
	char uid[TASK_COMM_LEN];
	int pid;
	int ppid;
	char cmd[MAX_CMD_LEN];
	int is_container;
};

struct namespace_info
{
	long cgroup_namespace;
};

/* definition of a sample sent to user-space from BPF program */
struct container_event
{
	struct process_event process;
	struct namespace_info namespace;
	char container_id[MAX_CONTAINER_LEN];
};

#endif