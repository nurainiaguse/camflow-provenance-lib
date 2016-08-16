/*
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
void flush_json( void );
void append_activity(char* json_element);
void append_agent(char* json_element);
void append_entity(char* json_element);
void append_message(char* json_element);
void append_relation(char* json_element);
void append_used(char* json_element);
void append_generated(char* json_element);
void append_informed(char* json_element);
void append_derived(char* json_element);

/* disclosing nodes and relations for provjson */
#define disclose_entity_ProvJSON(content, identifier) disclose_node_ProvJSON(MSG_DISC_ENTITY, content, identifier)
#define disclose_activity_ProvJSON(content, identifier) disclose_node_ProvJSON(MSG_DISC_ACTIVITY, content, identifier)
#define disclose_agent_ProvJSON(content, identifier) disclose_node_ProvJSON(MSG_DISC_AGENT, content, identifier)

int disclose_node_ProvJSON(uint32_t type, const char* content, prov_identifier_t* identifier);
int disclose_relation_ProvJSON(uint32_t type, prov_identifier_t* sender, prov_identifier_t* receiver);

/* struct to json functions */
/* TODO provide clean implementation? right now probably highly inneficient */
char* relation_to_json(struct relation_struct* e);
char* used_to_json(struct relation_struct* e);
char* generated_to_json(struct relation_struct* e);
char* informed_to_json(struct relation_struct* e);
char* derived_to_json(struct relation_struct* e);
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
