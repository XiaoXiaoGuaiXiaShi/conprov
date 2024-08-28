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
#ifndef __PROVENANCESPADEJSON_H
#define __PROVENANCESPADEJSON_H

/* struct to spade functions */
char* used_to_spade_json(struct relation_struct* e);
char* generated_to_spade_json(struct relation_struct* e);
char* informed_to_spade_json(struct relation_struct* e);
char* influenced_to_spade_json(struct relation_struct* e);
char* associated_to_spade_json(struct relation_struct* e);
char* derived_to_spade_json(struct relation_struct* e);
char* proc_to_spade_json(struct proc_prov_struct* n);
char* task_to_spade_json(struct task_prov_struct* n);
char* inode_to_spade_json(struct inode_prov_struct* n);
char* sb_to_spade_json(struct sb_struct* n);
char* msg_to_spade_json(struct msg_msg_struct* n);
char* shm_to_spade_json(struct shm_struct* n);
char* packet_to_spade_json(struct pck_struct* n);
char* addr_to_spade_json(struct address_struct* n);
char* pathname_to_spade_json(struct file_name_struct* n);
char* xattr_to_spade_json(struct xattr_prov_struct* n);
char* pckcnt_to_spade_json(struct pckcnt_struct* n);
char* arg_to_spade_json(struct arg_struct* n);
char* machine_to_spade_json(struct machine_struct *m);


void spade_json_append(char* buff);
void set_SPADEJSON_callback( void (*fcn)(char* json) );
void flush_spade_json();

#endif
