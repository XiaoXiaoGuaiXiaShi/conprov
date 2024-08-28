#ifndef __KERN_BPF_INODE_H
#define __KERN_BPF_INODE_H

#include "shared/prov_struct.h"
#include "shared/prov_types.h"
#include "kern/maps.h"
#include "kern/common.h"
#include "kern/node.h"

#define NULL ((void *)0)

#define __kernel_size_t
#define __kernel_fsid_t
#define __kernel_fd_set
#define statx_timestamp
#define statx
#include <linux/stat.h>
#undef __kernel_size_t
#undef __kernel_fsid_t
#undef __kernel_fd_set
#undef statx_timestamp
#undef statx

#define is_inode_dir(inode)             S_ISDIR(inode->i_mode)
#define is_inode_socket(inode)          S_ISSOCK(inode->i_mode)
#define is_inode_file(inode)            S_ISREG(inode->i_mode)

#define MAY_EXEC		0x00000001
#define MAY_WRITE		0x00000002
#define MAY_READ		0x00000004
#define MAY_APPEND		0x00000008
#define MAY_ACCESS		0x00000010
#define MAY_OPEN		0x00000020
#define MAY_CHDIR		0x00000040

#define FILE__EXECUTE           0x00000001UL
#define FILE__READ              0x00000002UL
#define FILE__APPEND            0x00000004UL
#define FILE__WRITE             0x00000008UL
#define DIR__SEARCH             0x00000010UL
#define DIR__WRITE              0x00000020UL
#define DIR__READ               0x00000040UL

#endif
