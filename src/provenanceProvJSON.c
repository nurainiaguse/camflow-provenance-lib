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
#include <netdb.h>
#include <pthread.h>

#include "provenancelib.h"
#include "provenancePovJSON.h"
#include "provenanceutils.h"

#define MAX_PROVJSON_BUFFER_LENGTH PATH_MAX*2

static pthread_mutex_t l_out =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_activity =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_agent =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_entity =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_edge =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static char activity[MAX_PROVJSON_BUFFER_LENGTH];
static char agent[MAX_PROVJSON_BUFFER_LENGTH];
static char entity[MAX_PROVJSON_BUFFER_LENGTH];
static char edge[MAX_PROVJSON_BUFFER_LENGTH];

bool writing_out = false;

static void (*print_json)(char* json);

void set_ProvJSON_callback( void (*fcn)(char* json) ){
  print_json = fcn;
}

static inline bool __append(char destination[MAX_PROVJSON_BUFFER_LENGTH], char* source){
  if (strlen(source) + 2 > MAX_PROVJSON_BUFFER_LENGTH - strlen(destination)){ // not enough space
    return false;
  }
  // add the comma
  if(destination[0]!='\0')
    strcat(destination, ",");
  strncat(destination, source, MAX_PROVJSON_BUFFER_LENGTH - strlen(destination) - 1); // copy up to free space
  return true;
}

#define JSON_START "{\"prefix\":{"
#define JSON_ACTIVITY "}, \"activity\":{"
#define JSON_AGENT "}, \"agent\":{"
#define JSON_ENTITY "}, \"entity\":{"
#define JSON_EDGE "}, \"edge\":{"
#define JSON_END "}}"

#define JSON_LENGTH (strlen(JSON_START)\
                      +strlen(JSON_ACTIVITY)\
                      +strlen(JSON_AGENT)\
                      +strlen(JSON_ENTITY)\
                      +strlen(JSON_EDGE)\
                      +strlen(JSON_END)\
                      +strlen(prefix_json())\
                      +strlen(activity)\
                      +strlen(agent)\
                      +strlen(entity)\
                      +strlen(edge)\
                      +1)

#define str_is_empty(str) (str[0]=='\0')
// we create the JSON string to be sent to the call back
static inline char* ready_to_print(){
  pthread_mutex_lock(&l_activity);
  pthread_mutex_lock(&l_agent);
  pthread_mutex_lock(&l_entity);
  pthread_mutex_lock(&l_edge);

  /* allocate memory */
  char* json = (char*)malloc(JSON_LENGTH * sizeof(char));
  json[0]='\0';

  strcat(json, JSON_START);
  strcat(json, prefix_json());

  /* recording activities */
  if(!str_is_empty(activity)){
    strcat(json, JSON_ACTIVITY);
    strcat(json, activity);
    memset(activity, '\0', MAX_PROVJSON_BUFFER_LENGTH);
  }

  /* recording agents */
  if(!str_is_empty(agent)){
    strcat(json, JSON_AGENT);
    strcat(json, agent);
    memset(agent, '\0', MAX_PROVJSON_BUFFER_LENGTH);
  }

  /* recording entities */
  if(!str_is_empty(entity)){
    strcat(json, JSON_ENTITY);
    strcat(json, entity);
    memset(entity, '\0', MAX_PROVJSON_BUFFER_LENGTH);
  }

  /* recording edges */
  if(!str_is_empty(edge)){
    strcat(json, JSON_EDGE);
    strcat(json, edge);
    memset(edge, '\0', MAX_PROVJSON_BUFFER_LENGTH);
  }

  strcat(json, JSON_END);

  pthread_mutex_unlock(&l_edge);
  pthread_mutex_unlock(&l_entity);
  pthread_mutex_unlock(&l_agent);
  pthread_mutex_unlock(&l_activity);
  return json;
}

static inline void json_append(pthread_mutex_t* l, char destination[MAX_PROVJSON_BUFFER_LENGTH], char* source){
  char* json;
  bool is_tasked=false;
  pthread_mutex_lock(l);
  // we cannot append buffer is full, need to print json out
  if(!__append(destination, source)){
    // we need to check that there is no one already printing the json
    pthread_mutex_lock(&l_out);
    if(!writing_out){
      writing_out = true;
      is_tasked = true;
    }
    pthread_mutex_unlock(&l_out);

    // we are tasked to print the json
    if(is_tasked){
      json = ready_to_print();
      print_json(json);
      pthread_mutex_lock(&l_out);
      writing_out = false;
      pthread_mutex_unlock(&l_out);
    }
    pthread_mutex_unlock(l);
    json_append(l, destination, source);
    return;
  }
  pthread_mutex_unlock(l);
}

void append_activity(char* json_element){
  json_append(&l_activity, activity, json_element);
}

void append_agent(char* json_element){
  json_append(&l_agent, agent, json_element);
}

void append_entity(char* json_element){
  json_append(&l_entity, entity, json_element);
}

void append_edge(char* json_element){
  json_append(&l_edge, edge, json_element);
}

static __thread char buffer[MAX_PROVJSON_BUFFER_LENGTH];

char* node_info_to_json(char* buf, struct node_identifier* n){
  sprintf(buf, "{\"cf:type\": %u, \"cf:id\":%llu, \"cf:boot_id\":%u, \"cf:machine_id\":%u, \"cf:version\":%u}", n->type, n->id, n->boot_id, n->machine_id, n->version);
  return buf;
}

char* edge_info_to_json(char* buf, struct edge_identifier* e){
  sprintf(buf, "{\"cf:type\": %u, \"cf:id\":%llu, \"cf:boot_id\":%u, \"cf:machine_id\":%u}", e->type, e->id, e->boot_id, e->machine_id);
  return buf;
}

static char* bool_str[] = {"false", "true"};

char* edge_to_json(struct edge_struct* e){
  char edge_info[1024];
  char* id = base64_encode(e->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  char* sender = base64_encode(e->snd.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  char* receiver = base64_encode(e->rcv.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\":{\"cf:edge_info\":%s, \"cf:type\":\"%s\", \"cf:allowed\":%s, \"cf:sender\":\"cf:%s\", \"cf:receiver\":\"cf:%s\"}",
    id,
    edge_info_to_json(edge_info, &e->identifier.edge_id),
    edge_str[e->type],
    bool_str[e->allowed],
    sender,
    receiver);
  free(id);
  free(sender);
  free(receiver);
  return buffer;
}

char* disc_to_json(struct disc_node_struct* n){
  char node_info[1024];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : { \"cf:node_info\": %s}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id));
  free(id);
  return buffer;
}

char* task_to_json(struct task_prov_struct* n){
  char node_info[1024];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : {\"node_info\":%s, \"user_id\":%u, \"group_id\":%u}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id),
    n->uid,
    n->gid);
  free(id);
  return buffer;
}

#define UUID_STR_SIZE 37
char* uuid_to_str(uint8_t* uuid, char* str, size_t size){
  if(size<37){
    sprintf(str, "UUID-ERROR");
    return str;
  }
  sprintf(str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    uuid[0], uuid[1], uuid[2], uuid[3]
    , uuid[4], uuid[5]
    , uuid[6], uuid[7]
    , uuid[8], uuid[9]
    , uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    return str;
}

static char STR_UNKNOWN[]= "unknown";
static char STR_BLOCK_SPECIAL[]= "block special";
static char STR_CHAR_SPECIAL[]= "char special";
static char STR_DIRECTORY[]= "directory";
static char STR_FIFO[]= "fifo";
static char STR_LINK[]= "link";
static char STR_FILE[]= "file";
static char STR_SOCKET[]= "socket";

static inline char* get_inode_type(mode_t mode){
  char* type=STR_UNKNOWN;
  if(S_ISBLK(mode))
    type=STR_BLOCK_SPECIAL;
  else if(S_ISCHR(mode))
    type=STR_CHAR_SPECIAL;
  else if(S_ISDIR(mode))
    type=STR_DIRECTORY;
  else if(S_ISFIFO(mode))
    type=STR_FIFO;
  else if(S_ISLNK(mode))
    type=STR_LINK;
  else if(S_ISREG(mode))
    type=STR_FILE;
  else if(S_ISSOCK(mode))
    type=STR_SOCKET;
  return type;
}

char* inode_to_json(struct inode_prov_struct* n){

  char msg_info[1024];
  char node_info[1024];
  char uuid[UUID_STR_SIZE];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : { \"cf:node_info\": %s, \"cf:user_id\":%u, \"cf:group_id\":%u, \"prov:type\":\"cf:%s\", \"cf:mode\":\"0X%04hhX\", \"cf:uuid\":\"%s\"}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id),
    n->uid,
    n->gid,
    get_inode_type(n->mode),
    n->mode,
    uuid_to_str(n->sb_uuid, uuid, UUID_STR_SIZE));
  free(id);
  return buffer;
}

char* sb_to_json(struct sb_struct* n){
  char node_info[1024];
  char uuid[UUID_STR_SIZE];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : {\"cf:node_info\":%s, \"cf:uuid\":\"%s\"}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id),
    uuid_to_str(n->uuid, uuid, UUID_STR_SIZE));
  free(id);
  return buffer;
}

char* msg_to_json(struct msg_msg_struct* n){
  char node_info[1024];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : {\"cf:node_info\":%s, \"cf:type\":%ld}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id),
    n->type);
  free(id);
  return buffer;
}

char* shm_to_json(struct shm_struct* n){
  char node_info[1024];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : {\"cf:node_info\":%s, \"cf:mode\":\"0X%04hhX\"}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id),
    n->mode);
  free(id);
  return buffer;
}

char* sock_to_json(struct sock_struct* n){
  char node_info[1024];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : {\"cf:node_info\":%s, \"cf:type\":%u, \"cf:family\":%u, \"cf:protocol\":%u}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id),
    n->type,
    n->family,
    n->protocol);
  free(id);
  return buffer;
}

char* str_msg_to_json(struct str_struct* n){
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : {\"cf:msg\":\"%s\"}",
    id,
    n->str);
  free(id);
  return buffer;
}

char* sockaddr_to_json(char* buf, struct sockaddr* addr, size_t length){
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];

  if(addr->sa_family == AF_INET){
    getnameinfo(addr, length, host, NI_MAXHOST, serv, NI_MAXSERV, 0);
    sprintf(buf, "{\"type\":\"AF_INET\", \"host\":\"%s\", \"serv\":\"%s\"}", host, serv);
  }else if(addr->sa_family == AF_INET6){
    getnameinfo(addr, length, host, NI_MAXHOST, serv, NI_MAXSERV, 0);
    sprintf(buf, "{\"type\":\"AF_INET6\", \"host\":\"%s\", \"serv\":\"%s\"}", host, serv);
  }else if(addr->sa_family == AF_UNIX){
    sprintf(buf, "{\"type\":\"AF_UNIX\", \"path\":\"%s\"}", ((struct sockaddr_un*)addr)->sun_path);
  }else{
    sprintf(buf, "{\"type\":\"OTHER\"}");
  }

  return buf;
}

char* addr_to_json(struct address_struct* n){
  char node_info[1024];
  char addr_info[PATH_MAX+1024];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : {\"cf:node_info\":%s, \"cf:address\":%s}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id),
    sockaddr_to_json(addr_info, &n->addr, n->length));
  free(id);
  return buffer;
}

char* pathname_to_json(struct file_name_struct* n){
  char node_info[1024];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : {\"cf:node_info\":%s, \"cf:pathname\":\"%s\"}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id),
    n->name);
  free(id);
  return buffer;
}

char* ifc_to_json(struct ifc_context_struct* n){
  char node_info[1024];
  char* id = base64_encode(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH);
  sprintf(buffer, "\"cf:%s\" : {\"cf:node_info\":%s, \"cf:ifc\":\"TODO\"}",
    id,
    node_info_to_json(node_info, &n->identifier.node_id));
  free(id);
  return buffer;
}

char* prefix_json(){
  return "\"prov\" : \"http://www.w3.org/ns/prov\", \"cf\":\"http://www.camflow.org\"";
}
