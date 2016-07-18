/*
*
* provenancelib.h
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Harvard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/

#ifndef __PROVENANCEPROVJSON_H
#define __PROVENANCEPROVJSON_H

#define MAX_PROVJSON_BUFFER_LENGTH PATH_MAX*2

/* struct to json functions */
/* TODO provide clean implementation? right now probably highly inneficient */
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
char* pathname_to_json(char* buffer, struct file_name_struct* n);
char* ifc_to_json(char* buffer, struct ifc_context_struct* n);
char* prefix_json();

#endif /* __PROVENANCEPROVJSON_H */
