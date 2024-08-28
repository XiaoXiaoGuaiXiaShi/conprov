#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/5/9 上午10:28
# @Author  : dqq
# @File    : capabilities_define.py
# 计算过程解释：在Linux内核capability.h里把CAP_NET_ADMIN的值定义成12，所以我们可以看到"CapEff"的值是"0000003fffffefff"，第4个数值是16进制的"e"，而不是f。这表示CAP_NET_ADMIN对应的第12-bit没有被置位了（0xefff = 0xffff & (~(1 << 12))），所以这个进程也就没有执行iptables命令的权限了。

syscall_name = {"304": "open_by_handle_at",
                "2": "open",
                "1000": "",
                "0": "read",
                "59": "execve",
                "58": "vfork"
                }

cap_name = {"0": "CAP_CHOWN",
            "1": "CAP_DAC_OVERRIDE",
            "2": "CAP_DAC_READ_SEARCH",
            "3": "CAP_FOWNER",
            "4": "CAP_FSETID",
            "5": "CAP_KILL",
            "6": "CAP_SETGID",
            "7": "CAP_SETUID",
            "8": "CAP_SETPCAP",
            "9": "CAP_LINUX_IMMUTABLE",
            "10": "CAP_NET_BIND_SERVICE",
            "11": "CAP_NET_BROADCAST",
            "12": "CAP_NET_ADMIN",
            "13": "CAP_NET_RAW",
            "14": "CAP_IPC_LOCK",
            "15": "CAP_IPC_OWNER",
            "16": "CAP_SYS_MODULE",
            "17": "CAP_SYS_RAWIO",
            "18": "CAP_SYS_CHROOT",
            "19": "CAP_SYS_PTRACE",
            "20": "CAP_SYS_PACCT",
            "21": "CAP_SYS_ADMIN",
            "22": "CAP_SYS_BOOT",
            "23": "CAP_SYS_NICE",
            "24": "CAP_SYS_RESOURCE",
            "25": "CAP_SYS_TIME",
            "26": "CAP_SYS_TTY_CONFIG",
            "27": "CAP_MKNOD",
            "28": "CAP_LEASE",
            "29": "CAP_AUDIT_WRITE",
            "30": "CAP_AUDIT_CONTROL",
            "31": "CAP_SETFCAP",
            "32": "CAP_MAC_OVERRIDE",
            "33": "CAP_MAC_ADMIN",
            "34": "CAP_SYSLOG",
            "35": "CAP_WAKE_ALARM",
            "36": "CAP_BLOCK_SUSPEND",
            "37": "CAP_AUDIT_READ",
            "38": "CAP_PERFMON",
            "39": "CAP_BPF",
            "40": "CAP_CHECKPOINT_RESTORE"
            }


def cap_hex_parser(cap_effective):
    capTextList = []
    back_eight = int(cap_effective, 16)
    for i in range(len(cap_name)):
        flag = back_eight & 0x1
        if flag == 1:
            capTextList.append(cap_name[str(i)])
        back_eight = back_eight >> 1
    return capTextList


def diff_cap(default_cap, capTextList):
    diff_cap_list = {}
    if default_cap == capTextList:
        pass
    else:
        # 新增的capabilities
        diff_cap_list = set(capTextList).difference(set(default_cap))
    return diff_cap_list


# test
# "00000000a80425fb": "CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_SYS_CHROOT,CAP_MKNOD,CAP_AUDIT_WRITE,CAP_SETFCAP"
# "00000000a80c25fb" : "CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_SYS_CHROOT,CAP_SYS_PTRACE,CAP_MKNOD,CAP_AUDIT_WRITE,CAP_SETFCAP"
# "00000000a82425fb": "CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_SYS_CHROOT,CAP_SYS_ADMIN,CAP_MKNOD,CAP_AUDIT_WRITE,CAP_SETFCAP"
# cap_hex_parser("00000000a80425fb")
# str = "00000" + "a80c25fb"
# print(str)
