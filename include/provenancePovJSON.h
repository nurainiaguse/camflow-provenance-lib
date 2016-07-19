/*
*
* provenanceProvJSON.h
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

void set_ProvJSON_callback( void (*fcn)(char* json) );
void append_activity(char* json_element);
void append_agent(char* json_element);
void append_entity(char* json_element);
void append_edge(char* json_element);

/* struct to json functions */
/* TODO provide clean implementation? right now probably highly inneficient */
char* edge_to_json(struct edge_struct* e);
char* disc_to_json(struct disc_node_struct* n);
char* task_to_json(struct task_prov_struct* n);
char* inode_to_json(struct inode_prov_struct* n);
char* sb_to_json(struct sb_struct* n);
char* msg_to_json(struct msg_msg_struct* n);
char* shm_to_json(struct shm_struct* n);
char* sock_to_json(struct sock_struct* n);
char* str_msg_to_json(struct str_struct* n);
char* addr_to_json(struct address_struct* n);
char* pathname_to_json(struct file_name_struct* n);
char* ifc_to_json(struct ifc_context_struct* n);
char* prefix_json();

#endif /* __PROVENANCEPROVJSON_H */
