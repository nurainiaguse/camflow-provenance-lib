/*
*
* provenancelib.h
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#ifndef __PROVENANCELIB_H
#define __PROVENANCELIB_H


#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/provenance.h>


static char* edge_str[]={"data", "create", "pass", "change", "mmap", "attach", "associate", "bind", "connect", "listen", "accept", "open", "parent", "version", "unknown"};

struct provenance_ops{
  void (*init)(void);
  void (*log_edge)(struct edge_struct*);
  void (*log_task)(struct task_prov_struct*);
  void (*log_inode)(struct inode_prov_struct*);
  void (*log_str)(struct str_struct*);
  void (*log_link)(struct link_struct*);
  void (*log_unlink)(struct unlink_struct*);
  void (*log_disc)(struct disc_node_struct*);
  void (*log_msg)(struct msg_msg_struct*);
  void (*log_shm)(struct shm_struct*);
  void (*log_sock)(struct sock_struct*);
  void (*log_address)(struct address_struct*);
  void (*log_file_name)(struct file_name_struct*);
  void (*log_ifc)(struct ifc_context_struct*);
};

/* provenance usher functions */
int provenance_register(struct provenance_ops* ops);
void provenance_stop(void);

/* security file manipulation */
int provenance_set_enable(bool v);
int provenance_set_all(bool v);
int provenance_set_opaque(bool v);
int provenance_disclose_node(struct disc_node_struct* node);
int provenance_disclose_edge(struct edge_struct* edge);
int provenance_self(struct task_prov_struct* self);

/* struct to json functions */
/* TODO detach from main library? provide clean implementation? right now probably highly inneficient */
char* edge_to_json(char* buffer, struct edge_struct* e);
char* disc_to_json(char* buffer, struct disc_node_struct* n);
char* task_to_json(char* buffer, struct task_prov_struct* n);
char* inode_to_json(char* buffer, struct inode_prov_struct* n);
char* sb_to_json(char* buffer, struct sb_struct* n);
char* msg_to_json(char* buffer, struct msg_msg_struct* n);
char* shm_to_json(char* buffer, struct shm_struct* n);
char* sock_to_json(char* buffer, struct sock_struct* n);
char* str_msg_to_json(char* buffer, struct str_struct* n);
char* addr_to_json(char* buffer, struct address_struct* n);
char* link_to_json(char* buffer, struct link_struct* n);
char* unlink_to_json(char* buffer, struct unlink_struct* n);
char* pathname_to_json(char* buffer, struct file_name_struct* n);
char* ifc_to_json(char* buffer, struct ifc_context_struct* n);

#endif /* __PROVENANCELIB_H */
