/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * Copyright (C) 2015-2016 University of Cambridge
 * Copyright (C) 2016-2017 Harvard University
 * Copyright (C) 2017-2018 University of Cambridge
 * Copyright (C) 2018-202O University of Bristol
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <sys/utsname.h>

#include "usr/json_common.h"
#include "shared/prov_struct.h"
#include "usr/types.h"
#include "usr/utils.h"
#include "shared/prov_types.h"

__thread char buffer[MAX_JSON_BUFFER_LENGTH];
#define BUFFER_LENGTH (MAX_JSON_BUFFER_LENGTH - strnlen(buffer, MAX_JSON_BUFFER_LENGTH))
static __thread char id[PROV_ID_STR_LEN];
static __thread char from[PROV_ID_STR_LEN];
static __thread char to[PROV_ID_STR_LEN];
char date[256];
pthread_rwlock_t date_lock = PTHREAD_RWLOCK_INITIALIZER;
char *ro_path;
char full_path[256];

static inline void __init_node(char *type, char *id, const struct node_identifier *n)
{
  buffer[0] = '\0';
  update_time();
  strncat(buffer, "{", BUFFER_LENGTH);
  __add_string_attribute("type", type, false);
  __add_string_attribute("id", id, true);
  strncat(buffer, ",\"annotations\": {", BUFFER_LENGTH);
  __add_uint64_attribute("object_id", n->id, false);
  __add_string_attribute("object_type", node_id_to_str(n->type), true);
  __add_uint32_attribute("version", n->version, true);
  __add_date_attribute(true);
}

static inline void __close_node(void)
{
  strncat(buffer, "}}\n", BUFFER_LENGTH);
}

static inline void __init_relation(char *type,
                                   char *from,
                                   char *to,
                                   char *id,
                                   const struct relation_identifier *e)
{
  buffer[0] = '\0';
  update_time();
  strncat(buffer, "{", BUFFER_LENGTH);
  __add_string_attribute("type", type, false);
  __add_string_attribute("from", from, true);
  __add_string_attribute("to", to, true);
  strncat(buffer, ",\"annotations\": {", BUFFER_LENGTH);
  __add_string_attribute("id", id, false);
  __add_uint64_attribute("relation_id", e->id, true);
  __add_string_attribute("relation_type", relation_id_to_str(e->type), true);
  __add_date_attribute(true);
}

#define NODE_START(type)                                                               \
  ID_ENCODE(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN); \
  __init_node(type, id, &(n->identifier.node_id));                                     \

#define NODE_END() __close_node()

#define RELATION_START(type)                                                           \
  ID_ENCODE(e->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN); \
  ID_ENCODE(e->snd.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, from, PROV_ID_STR_LEN);      \
  ID_ENCODE(e->rcv.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, to, PROV_ID_STR_LEN);        \
  __init_relation(type, to, from, id, &(e->identifier.relation_id));                   \

#define RELATION_END() __close_node()

static inline void __relation_to_spade_json(struct relation_struct *e)
{
  if (e->allowed == FLOW_ALLOWED)
    __add_string_attribute("allowed", "true", true);
  else
    __add_string_attribute("allowed", "false", true);
  if (e->set == FILE_INFO_SET && e->offset > 0)
    __add_int64_attribute("offset", e->offset, true); // just offset for now
  __add_uint64hex_attribute("flags", e->flags, true);
  __add_uint64hex_attribute("cap", e->cap, true);
  __add_int64_attribute("syscall", e->syscall_nid, true);
  __add_string_attribute("from_type", node_id_to_str(e->rcv.node_id.type), true);
  __add_string_attribute("to_type", node_id_to_str(e->snd.node_id.type), true);
}

char *used_to_spade_json(struct relation_struct *e)
{
  RELATION_START("Used");
  __relation_to_spade_json(e);
  RELATION_END();
  return buffer;
}

char *generated_to_spade_json(struct relation_struct *e)
{
  RELATION_START("WasGeneratedBy");
  __relation_to_spade_json(e);
  RELATION_END();
  return buffer;
}

char *informed_to_spade_json(struct relation_struct *e)
{
  RELATION_START("WasInformedBy");
  __relation_to_spade_json(e);
  RELATION_END();
  return buffer;
}

char *influenced_to_spade_json(struct relation_struct *e)
{
  RELATION_START("WasInfluencedBy");
  __relation_to_spade_json(e);
  RELATION_END();
  return buffer;
}

char *associated_to_spade_json(struct relation_struct *e)
{
  RELATION_START("WasAssociatedWith");
  __relation_to_spade_json(e);
  RELATION_END();
  return buffer;
}

char *derived_to_spade_json(struct relation_struct *e)
{
  RELATION_START("WasDerivedFrom");
  __relation_to_spade_json(e);
  RELATION_END();
  return buffer;
}

char *proc_to_spade_json(struct proc_prov_struct *n)
{
  NODE_START("Entity");
  __add_uint32_attribute("tid", n->tid, true);
  __add_uint32_attribute("pid", n->pid, true);
  __add_string_attribute("comm", n->comm, true);
  __add_uint32_attribute("userns", n->userns, true);
  __add_uint32hex_attribute("CapEff0", n->cap_effective[0], true);
  __add_uint32hex_attribute("CapEff1", n->cap_effective[1], true);
  NODE_END();
  return buffer;
}

char *task_to_spade_json(struct task_prov_struct *n)
{
  NODE_START("Activity");
  __add_uint32_attribute("tid", n->tid, true);
  __add_uint32_attribute("pid", n->pid, true);
  __add_uint32_attribute("secid", n->secid, true);
  __add_uint32_attribute("pidns", n->pidns, true);
  __add_uint32_attribute("cgroupns", n->cgroupns, true);
  __add_uint32_attribute("ipcns", n->ipcns, true);
  __add_uint32_attribute("mntns", n->mntns, true);
  __add_uint32_attribute("userns", n->userns, true);
  __add_string_attribute("comm", n->comm, true);
  __add_string_attribute("cwd", n->cwd, true);
  __add_uint32hex_attribute("CapEff0", n->cap_effective[0], true);
  __add_uint32hex_attribute("CapEff1", n->cap_effective[1], true);
  NODE_END();
  return buffer;
}

static __thread char uuid[UUID_STR_SIZE];

char *inode_to_spade_json(struct inode_prov_struct *n)
{
  NODE_START("Entity");
  __add_uint32_attribute("uid", n->uid, true);
  __add_uint32_attribute("gid", n->gid, true);
  __add_uint32hex_attribute("mode", n->mode, true);
  __add_uint32_attribute("secid", n->secid, true);
  __add_uint32_attribute("ino", n->ino, true);
  NODE_END();
  return buffer;
}

char *addr_to_spade_json(struct address_struct *n)
{
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];
  int err;
  struct sockaddr *ad = (struct sockaddr *)(n->addr);

  NODE_START("Entity");
  if (ad->sa_family == AF_INET)
  {
    err = getnameinfo(ad, sizeof(struct sockaddr_in), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    __add_string_attribute("type", "AF_INET", true);
    if (err < 0)
    {
      __add_string_attribute("host", "could not resolve", true);
      __add_string_attribute("service", "could not resolve", true);
      __add_string_attribute("error", gai_strerror(err), true);
    }
    else
    {
      __add_string_attribute("host", host, true);
      __add_string_attribute("service", serv, true);
    }
  }
  else if (ad->sa_family == AF_INET6)
  {
    err = getnameinfo(ad, sizeof(struct sockaddr_in6), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    __add_string_attribute("type", "AF_INET6", true);
    if (err < 0)
    {
      __add_string_attribute("host", "could not resolve", true);
      __add_string_attribute("service", "could not resolve", true);
      __add_string_attribute("error", gai_strerror(err), true);
    }
    else
    {
      __add_string_attribute("host", host, true);
      __add_string_attribute("service", serv, true);
    }
  }
  else if (ad->sa_family == AF_UNIX)
  {
    __add_string_attribute("type", "AF_UNIX", true);
    __add_string_attribute("path", ((struct sockaddr_un *)ad)->sun_path, true);
  }
  else
  {
    err = getnameinfo(ad, sizeof(struct sockaddr), host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    __add_int32_attribute("type", ad->sa_family, true);
    if (err < 0)
    {
      __add_string_attribute("host", "could not resolve", true);
      __add_string_attribute("service", "could not resolve", true);
      __add_string_attribute("error", gai_strerror(err), true);
    }
    else
    {
      __add_string_attribute("host", host, true);
      __add_string_attribute("service", serv, true);
    }
  }
  NODE_END();
  return buffer;
}

char *pathname_to_spade_json(struct file_name_struct *n)
{
  int i;
  NODE_START("Entity");
  // dirty fix
  // for (i = 0; i < n->length; i++)
  // {
  //   if (n->name[i] == '\\')
  //     n->name[i] = '/';
  // }
  if(n->overlay_flag==6)
  {
      strcpy(full_path, ro_path);
      // printf("ro_path:%s\n", full_path);
      strcat(full_path, n->name);
  }
  else if (n->overlay_flag==7)
  {
    strcpy(full_path, "/sys/fs/cgroup/memory");
    // printf("ro_path:%s\n", full_path);
    strcat(full_path, n->name);
  }
  else if (n->overlay_flag==9)
  {
    strcpy(full_path, n->host_path);
    // printf("full_path:%s\n", full_path);
    char tmp_path[170];
    int j = 0;
    for (i = (strlen(n->mount_path)+1); i < strlen(n->name); i++)
    {
      tmp_path[j] = (n->name)[i];
      j++;
    }
    strcat(full_path, tmp_path);
    // printf("full_path:%s\n", full_path);
  }
  else
  {
      strcpy(full_path, "");
      strcat(full_path, n->name);
  }
  __add_string_attribute("pathname", full_path, true);
  __add_uint32_attribute("type", n->overlay_flag, true);
  NODE_END();
  return buffer;
}

static char *json;
static inline void init_buffer(void)
{
  json = (char *)malloc(MAX_JSON_BUFFER_LENGTH);
  memset(buffer, 0, MAX_JSON_BUFFER_LENGTH);
  memset(json, 0, MAX_JSON_BUFFER_LENGTH);
}

static void (*print_json)(char *json);

void set_SPADEJSON_callback(void (*fcn)(char *json))
{
  init_buffer();
  print_json = fcn;
}

static pthread_mutex_t l_json = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static inline bool __append(char *buff)
{
  pthread_mutex_lock(&l_json);
  if (strlen(buff) + 2 > MAX_JSON_BUFFER_LENGTH - strlen(json) - 1)
  { // not enough space
    pthread_mutex_unlock(&l_json);
    return false;
  }
  strncat(json, buff, MAX_JSON_BUFFER_LENGTH - strlen(json) - 1); // copy up to free space
  pthread_mutex_unlock(&l_json);
  return true;
}

static bool writing_out = false;
static pthread_mutex_t l_flush = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

void flush_spade_json()
{
  bool should_flush = false;

  pthread_mutex_lock(&l_flush);
  if (!writing_out)
  {
    writing_out = true;
    should_flush = true;
    update_time(); // we update the time
  }
  pthread_mutex_unlock(&l_flush);

  if (should_flush)
  {
    pthread_mutex_lock(&l_json);
    if (json[0] == 0)
    {
      pthread_mutex_unlock(&l_json);
      writing_out = false;
      return;
    }
    print_json(json);
    memset(json, 0, MAX_JSON_BUFFER_LENGTH);
    pthread_mutex_unlock(&l_json);
    pthread_mutex_lock(&l_flush);
    writing_out = false;
    pthread_mutex_unlock(&l_flush);
  }
}

void spade_json_append(char *buff)
{
  // we cannot append buffer is full, need to print json out
  if (!__append(buff))
  {
    flush_spade_json();
    spade_json_append(buff);
    return;
  }
}
