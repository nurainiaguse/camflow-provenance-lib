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
#include <linux/camflow.h>
#include <sys/utsname.h>

#include "provenancelib.h"
#include "provenancePovJSON.h"
#include "provenanceutils.h"

#define MAX_PROVJSON_BUFFER_LENGTH PATH_MAX*2

struct taint_entry{
  uint64_t taint_id;
  char* taint_name;
  struct taint_entry* next;
};

struct taint_entry taint_list = { .taint_id = 0, .taint_name = "test_tain", .next = NULL };

int add_taint(const uint64_t id, const char* name){
  struct taint_entry* n = &taint_list;
  struct taint_entry* tmp = (struct taint_entry*)malloc(sizeof(struct taint_entry));
  char* str = (char*)malloc(strlen(name)+1);
  strcpy(str, name);
  while(true){
    if(n->next!=NULL){
      n = n->next;
    }else{
      tmp->taint_id=id;
      tmp->taint_name=str;
      tmp->next=NULL;
      n->next=tmp;
      return 0;
    }
  }
}

static pthread_mutex_t l_flush =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_activity =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_agent =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_entity =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_relation =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_used =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_generated =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_informed =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_derived =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t l_message =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static char activity[MAX_PROVJSON_BUFFER_LENGTH];
static char agent[MAX_PROVJSON_BUFFER_LENGTH];
static char entity[MAX_PROVJSON_BUFFER_LENGTH];
static char relation[MAX_PROVJSON_BUFFER_LENGTH];
static char used[MAX_PROVJSON_BUFFER_LENGTH];
static char generated[MAX_PROVJSON_BUFFER_LENGTH];
static char informed[MAX_PROVJSON_BUFFER_LENGTH];
static char derived[MAX_PROVJSON_BUFFER_LENGTH];
static char message[MAX_PROVJSON_BUFFER_LENGTH];

bool writing_out = false;

static void (*print_json)(char* json);

int disclose_node_ProvJSON(uint32_t type, const char* content, prov_identifier_t* identifier){
  int err;
  struct disc_node_struct node;

  strncpy(node.content, content, PATH_MAX);
  node.length=strnlen(content, PATH_MAX);
  node.identifier.node_id.type=type;

  if(err = provenance_disclose_node(&node)<0){
    return err;
  }
  memcpy(identifier, &node.identifier, sizeof(prov_identifier_t));
  return err;
}

int disclose_relation_ProvJSON(uint32_t type, prov_identifier_t* sender, prov_identifier_t* receiver){
  struct relation_struct relation;
  relation.type=type;
  relation.allowed=true;
  memcpy(&relation.snd, sender, sizeof(prov_identifier_t));
  memcpy(&relation.rcv, receiver, sizeof(prov_identifier_t));
  return provenance_disclose_relation(&relation);
}

void set_ProvJSON_callback( void (*fcn)(char* json) ){
  print_json = fcn;
}

static inline bool __append(char destination[MAX_PROVJSON_BUFFER_LENGTH], char* source){
  if (strlen(source) + 2 > MAX_PROVJSON_BUFFER_LENGTH - strlen(destination) - 1){ // not enough space
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
#define JSON_MESSAGE "}, \"message\":{"
#define JSON_RELATION "}, \"relation\":{"
#define JSON_USED "}, \"used\":{"
#define JSON_GENERATED "}, \"wasGeneratedBy\":{"
#define JSON_INFORMED "}, \"wasInformedBy\":{"
#define JSON_DERIVED "}, \"wasDerivedFrom\":{"
#define JSON_END "}}"

#define JSON_LENGTH (strlen(JSON_START)\
                      +strlen(JSON_ACTIVITY)\
                      +strlen(JSON_AGENT)\
                      +strlen(JSON_ENTITY)\
                      +strlen(JSON_MESSAGE)\
                      +strlen(JSON_RELATION)\
                      +strlen(JSON_USED)\
                      +strlen(JSON_GENERATED)\
                      +strlen(JSON_INFORMED)\
                      +strlen(JSON_DERIVED)\
                      +strlen(JSON_END)\
                      +strlen(prefix_json())\
                      +strlen(activity)\
                      +strlen(agent)\
                      +strlen(entity)\
                      +strlen(message)\
                      +strlen(relation)\
                      +strlen(used)\
                      +strlen(generated)\
                      +strlen(derived)\
                      +strlen(informed)\
                      +1)

#define str_is_empty(str) (str[0]=='\0')

#define cat_prov(prefix, data, lock)     if(!str_is_empty(data)){ \
                                              content=true; \
                                              strcat(json, prefix); \
                                              strcat(json, data); \
                                              memset(data, '\0', MAX_PROVJSON_BUFFER_LENGTH); \
                                            } \
                                            pthread_mutex_unlock(&lock);

// we create the JSON string to be sent to the call back
static inline char* ready_to_print(){
  char* json;
  bool content=false;

  pthread_mutex_lock(&l_derived);
  pthread_mutex_lock(&l_informed);
  pthread_mutex_lock(&l_generated);
  pthread_mutex_lock(&l_used);
  pthread_mutex_lock(&l_relation);
  pthread_mutex_lock(&l_message);
  pthread_mutex_lock(&l_entity);
  pthread_mutex_lock(&l_agent);
  pthread_mutex_lock(&l_activity);

  json = (char*)malloc(JSON_LENGTH * sizeof(char));
  json[0]='\0';

  strcat(json, JSON_START);
  strcat(json, prefix_json());

  cat_prov(JSON_ACTIVITY, activity, l_activity);
  cat_prov(JSON_AGENT, agent, l_agent);
  cat_prov(JSON_ENTITY, entity, l_entity);
  cat_prov(JSON_MESSAGE, message, l_message);
  cat_prov(JSON_RELATION, relation, l_relation);
  cat_prov(JSON_USED, used, l_used);
  cat_prov(JSON_GENERATED, generated, l_generated);
  cat_prov(JSON_INFORMED, informed, l_informed);
  cat_prov(JSON_DERIVED, derived, l_derived);

  if(!content){
    free(json);
    return NULL;
  }

  strcat(json, JSON_END);
  return json;
}

void flush_json(){
  bool should_flush=false;
  char* json;

  pthread_mutex_lock(&l_flush);
  if(!writing_out){
    writing_out = true;
    should_flush = true;
  }
  pthread_mutex_unlock(&l_flush);

  if(should_flush){
    json = ready_to_print();
    if(json!=NULL){
      print_json(json);
      free(json);
    }
    pthread_mutex_lock(&l_flush);
    writing_out = false;
    pthread_mutex_unlock(&l_flush);
  }
}

static inline void json_append(pthread_mutex_t* l, char destination[MAX_PROVJSON_BUFFER_LENGTH], char* source){
  pthread_mutex_lock(l);
  // we cannot append buffer is full, need to print json out
  if(!__append(destination, source)){
    flush_json();
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

void append_message(char* json_element){
  json_append(&l_message, message, json_element);
}

void append_relation(char* json_element){
  json_append(&l_relation, relation, json_element);
}

void append_used(char* json_element){
  json_append(&l_used, used, json_element);
}

void append_generated(char* json_element){
  json_append(&l_generated, generated, json_element);
}

void append_informed(char* json_element){
  json_append(&l_informed, informed, json_element);
}

void append_derived(char* json_element){
  json_append(&l_derived, derived, json_element);
}

static __thread char buffer[MAX_PROVJSON_BUFFER_LENGTH];

static __thread char id[PROV_ID_STR_LEN];
static __thread char sender[PROV_ID_STR_LEN];
static __thread char receiver[PROV_ID_STR_LEN];
static __thread char parent_id[PROV_ID_STR_LEN];
static __thread char taint[PATH_MAX];

#define RELATION_PREP_IDs(e) ID_ENCODE(e->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);\
                        ID_ENCODE(e->snd.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, sender, PROV_ID_STR_LEN);\
                        ID_ENCODE(e->rcv.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, receiver, PROV_ID_STR_LEN)

#define DISC_PREP_IDs(n) ID_ENCODE(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN);\
                        ID_ENCODE(n->parent.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, parent_id, PROV_ID_STR_LEN)

#define NODE_PREP_IDs(n) ID_ENCODE(n->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN)

#define PACKET_PREP_IDs(p) ID_ENCODE(p->identifier.buffer, PROV_IDENTIFIER_BUFFER_LENGTH, id, PROV_ID_STR_LEN)

#define PROV_PREP_TAINT(n) TAINT_ENCODE(n->taint, PROV_N_BYTES, taint, TAINT_STR_LEN)

static void prov_prep_taint(const uint8_t bloom[PROV_N_BYTES]){
  struct taint_entry* tmp = &taint_list;
  bool first=true;
  if(prov_bloom_empty(bloom)){
    strncpy(taint, "[]", PATH_MAX);
  }else{
    taint[0]='\0';
    strcat(taint, "[");
    do{
      if( prov_bloom_in(bloom, tmp->taint_id) ){
        if(!first){
          strcat(taint, ",");
        }
        strcat(taint, "\"");
        strcat(taint, tmp->taint_name);
        strcat(taint, "\"");
        first=false;
      }
      tmp = tmp->next;
    }while(tmp!=NULL);
    strcat(taint, "]");
  }
}

static char* time_info_to_json(char* buf){
  int millisec;
  struct tm* tm;
  struct timeval tv;
  char str[256];

  gettimeofday(&tv, NULL);
  millisec = (int)(tv.tv_usec/1000.0);
  if (millisec>=1000) { // Allow for rounding up to nearest second
    millisec -=1000;
    tv.tv_sec++;
  }

  buf[0]='\0';
  strcat(buf, ",\"cf:date\":\"");
  tm = gmtime(&tv.tv_sec);
  strftime(str, 30,"%Y:%m:%dT%H:%M:%S", tm);
  strcat(buf, str);
  strcat(buf, ".");
  sprintf(str,"%03d",millisec);
  strcat(buf, str);
  strcat(buf, "\"");
  return buf;
}

static char* node_info_to_json(char* buf, struct node_identifier* n){
  char tmp[256];
  buf[0]='\0';
  strcat(buf, "\"cf:type\":");
  strcat(buf, utoa(n->type, tmp, DECIMAL));
  strcat(buf, ",\"cf:id\":");
  strcat(buf, ulltoa(n->id, tmp, DECIMAL));
  strcat(buf, ",\"cf:boot_id\":");
  strcat(buf, utoa(n->boot_id, tmp, DECIMAL));
  strcat(buf, ",\"cf:machine_id\":");
  strcat(buf, utoa(n->machine_id, tmp, DECIMAL));
  strcat(buf, ",\"cf:version\":");
  strcat(buf, utoa(n->version, tmp, DECIMAL));
  strcat(buf, time_info_to_json(tmp));
  return buf;
}

static char* relation_info_to_json(char* buf, struct relation_identifier* e){
  char tmp[256];
  buf[0]='\0';
  strcat(buf, "\"cf:id\":");
  strcat(buf, ulltoa(e->id, tmp, DECIMAL));
  strcat(buf, ",\"cf:boot_id\":");
  strcat(buf, utoa(e->boot_id, tmp, DECIMAL));
  strcat(buf, ",\"cf:machine_id\":");
  strcat(buf, utoa(e->machine_id, tmp, DECIMAL));
  strcat(buf, time_info_to_json(tmp));
  return buf;
}

static char* bool_str[] = {"false", "true"};

static char* __relation_to_json(struct relation_struct* e, const char* snd, const char* rcv){
  char relation_info[1024];
  RELATION_PREP_IDs(e);
  prov_prep_taint(e->taint);
  buffer[0]='\0';
  strcat(buffer, "\"cf:");
  strcat(buffer, id);
  strcat(buffer, "\":{");
  strcat(buffer, relation_info_to_json(relation_info, &e->identifier.relation_id));
  strcat(buffer, ",\"cf:taint\":");
  strcat(buffer, taint);
  strcat(buffer, ",\"cf:type\":\"");
  strcat(buffer, relation_str(e->type));
  strcat(buffer, "\",\"prov:label\":\"");
  strcat(buffer, relation_str(e->type));
  strcat(buffer, "\",\"cf:allowed\":\"");
  strcat(buffer, bool_str[e->allowed]);
  strcat(buffer, "\",\"");
  strcat(buffer, snd);
  strcat(buffer, "\":\"cf:");
  strcat(buffer, sender);
  strcat(buffer, "\",\"");
  strcat(buffer, rcv);
  strcat(buffer, "\":\"cf:");
  strcat(buffer, receiver);
  strcat(buffer, "\"}");
  return buffer;
}

char* relation_to_json(struct relation_struct* e){
  return __relation_to_json(e, "cf:sender", "cf:receiver");
}

char* used_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:entity", "prov:activity");
}

char* generated_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:activity", "prov:entity");
}

char* informed_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:informant", "prov:informed");
}

char* derived_to_json(struct relation_struct* e){
  return __relation_to_json(e, "prov:usedEntity", "prov:generatedEntity");
}

#define catnodestart(buffer, n) buffer[0]='\0';strcat(buffer, "\"cf:");strcat(buffer, id);strcat(buffer, "\":{");strcat(buffer, node_info_to_json(node_info, &n->identifier.node_id));strcat(buffer, ",\"cf:taint\":");strcat(buffer, taint);
#define catlabel(type, content) strcat(buffer, ",\"prov:label\":\"[");strcat(buffer, type);strcat(buffer, "] ");strcat(buffer,content);strcat(buffer, "\"");

char* disc_to_json(struct disc_node_struct* n){
  char node_info[1024];
  DISC_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  strcat(buffer, ",\"cf:hasParent\":\"cf:");
  strcat(buffer, parent_id);
  if(n->length > 0){
    strcat(buffer, "\",");
    strcat(buffer, n->content);
    strcat(buffer, "}");
  }else{
    strcat(buffer, "\"}");
  }
  return buffer;
}

#define catuid(buffer, n_uid) strcat(buffer, ",\"cf:uid\":");strcat(buffer, utoa(n_uid, tmp, DECIMAL));
#define catgid(buffer, n_gid) strcat(buffer, ",\"cf:gid\":");strcat(buffer, utoa(n_gid, tmp, DECIMAL));

char* task_to_json(struct task_prov_struct* n){
  char node_info[1024];
  char tmp[33];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  catuid(buffer, n->uid);
  catgid(buffer, n->gid);
  catlabel("task", utoa(n->identifier.node_id.version, tmp, DECIMAL));
  strcat(buffer, "}");
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

static const char STR_UNKNOWN[]= "unknown";
static const char STR_BLOCK_SPECIAL[]= "block special";
static const char STR_CHAR_SPECIAL[]= "char special";
static const char STR_DIRECTORY[]= "directory";
static const char STR_FIFO[]= "fifo";
static const char STR_LINK[]= "link";
static const char STR_FILE[]= "file";
static const char STR_SOCKET[]= "socket";

static inline const char* get_inode_type(mode_t mode){
  if(S_ISBLK(mode))
    return STR_BLOCK_SPECIAL;
  else if(S_ISCHR(mode))
    return STR_CHAR_SPECIAL;
  else if(S_ISDIR(mode))
    return STR_DIRECTORY;
  else if(S_ISFIFO(mode))
    return STR_FIFO;
  else if(S_ISLNK(mode))
    return STR_LINK;
  else if(S_ISREG(mode))
    return STR_FILE;
  else if(S_ISSOCK(mode))
    return STR_SOCKET;
  return STR_UNKNOWN;
}


#define catuuid(buffer, n_uuid) strcat(buffer, ",\"cf:uuid\":\"");strcat(buffer, uuid_to_str(n_uuid, uuid, UUID_STR_SIZE));strcat(buffer, "\"");
#define catmode(buffer, n_mode) strcat(buffer, ",\"cf:mode\":\"0X");strcat(buffer, utoa(n->mode, tmp, HEX));strcat(buffer, "\"");

char* inode_to_json(struct inode_prov_struct* n){
  char msg_info[1024];
  char node_info[1024];
  char uuid[UUID_STR_SIZE];
  char tmp[65];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  catuid(buffer, n->uid);
  catgid(buffer, n->gid);
  strcat(buffer, ",\"prov:type\":\"cf:");
  strcat(buffer, get_inode_type(n->mode));
  strcat(buffer, "\"");
  catmode(buffer, n->mode);
  catuuid(buffer, n->sb_uuid);
  catlabel(get_inode_type(n->mode), utoa(n->identifier.node_id.version, tmp, DECIMAL));
  strcat(buffer, "}");
  return buffer;
}

char* sb_to_json(struct sb_struct* n){
  char node_info[1024];
  char uuid[UUID_STR_SIZE];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  catuuid(buffer, n->uuid);
  strcat(buffer, "}");
  return buffer;
}

char* msg_to_json(struct msg_msg_struct* n){
  char node_info[1024];
  char tmp[65];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  strcat(buffer, ",\"cf:type\":");
  strcat(buffer, ulltoa(n->type, tmp, DECIMAL));
  strcat(buffer, "}");
  return buffer;
}

char* shm_to_json(struct shm_struct* n){
  char node_info[1024];
  char tmp[33];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  catmode(buffer, n->mode);
  strcat(buffer, "}");
  return buffer;
}

char* sock_to_json(struct sock_struct* n){
  char node_info[1024];
  char tmp[33];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  strcat(buffer, ",\"cf:sock_type\":");
  strcat(buffer, utoa(n->type, tmp, DECIMAL));
  strcat(buffer, ",\"cf:family\":");
  strcat(buffer, utoa(n->family, tmp, DECIMAL));
  strcat(buffer, ",\"cf:protocol\":");
  strcat(buffer, utoa(n->protocol, tmp, DECIMAL));
  catlabel("sock", "TODO");
  strcat(buffer, "}");
  return buffer;
}

char* format_ip(char* buffer, uint32_t ip){
    char tmp[8];
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    buffer[0]='\0';
    strcat(buffer, utoa(bytes[0], tmp, DECIMAL));
    strcat(buffer, ".");
    strcat(buffer, utoa(bytes[1], tmp, DECIMAL));
    strcat(buffer, ".");
    strcat(buffer, utoa(bytes[2], tmp, DECIMAL));
    strcat(buffer, ".");
    strcat(buffer, utoa(bytes[3], tmp, DECIMAL));
    return buffer;
}

#define snd_addr(buffer, p) \
  strcat(buffer, format_ip(tmp, p->identifier.packet_id.snd_ip));\
  strcat(buffer, ":");\
  strcat(buffer, utoa(p->identifier.packet_id.snd_port, tmp, DECIMAL));

#define rcv_addr(buffer, p) \
  strcat(buffer, format_ip(tmp, p->identifier.packet_id.rcv_ip));\
  strcat(buffer, ":");\
  strcat(buffer, utoa(p->identifier.packet_id.rcv_port, tmp, DECIMAL));

char* packet_to_json(struct pck_struct* p){
  char tmp[256];
  PACKET_PREP_IDs(p);
  buffer[0]='\0';
  strcat(buffer, "\"cf:");
  strcat(buffer, id);
  strcat(buffer, "\":{");
  strcat(buffer, "\"cf:id\":");
  strcat(buffer, utoa(p->identifier.packet_id.id, tmp, DECIMAL));
  strcat(buffer, ",\"cf:seq\":");
  strcat(buffer, utoa(p->identifier.packet_id.seq, tmp, DECIMAL));
  strcat(buffer, time_info_to_json(tmp));
  strcat(buffer, ",\"cf:sender\":\"");
  snd_addr(buffer, p);
  strcat(buffer, "\",\"cf:receiver\":\"");
  rcv_addr(buffer, p);
  strcat(buffer, "\",\"prov:label\":\"[packet] ");
  snd_addr(buffer, p);
  strcat(buffer, "->");
  rcv_addr(buffer, p);
  strcat(buffer, " (");
  strcat(buffer, utoa(p->identifier.packet_id.id, tmp, DECIMAL));
  strcat(buffer, ")\"}");
  return buffer;
}

char* str_msg_to_json(struct str_struct* n){
  char node_info[1024];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  strcat(buffer, ",\"cf:message\":\"");
  strcat(buffer, n->str);
  strcat(buffer, "\"}");
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

char* sockaddr_to_label(char* buf, struct sockaddr* addr, size_t length){
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];

  if(addr->sa_family == AF_INET){
    getnameinfo(addr, length, host, NI_MAXHOST, serv, NI_MAXSERV, 0);
    sprintf(buf, "IPV4 %s", host);
  }else if(addr->sa_family == AF_INET6){
    getnameinfo(addr, length, host, NI_MAXHOST, serv, NI_MAXSERV, 0);
    sprintf(buf, "IPV6 %s", host);
  }else if(addr->sa_family == AF_UNIX){
    sprintf(buf, "UNIX %s", ((struct sockaddr_un*)addr)->sun_path);
  }else{
    sprintf(buf, "OTHER");
  }

  return buf;
}

char* addr_to_json(struct address_struct* n){
  char node_info[1024];
  char addr_info[PATH_MAX+1024];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  strcat(buffer, ",\"cf:address\":");
  strcat(buffer, sockaddr_to_json(addr_info, &n->addr, n->length));
  catlabel("address", sockaddr_to_label(addr_info, &n->addr, n->length));
  strcat(buffer, "}");
  return buffer;
}

char* pathname_to_json(struct file_name_struct* n){
  char node_info[1024];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  strcat(buffer, ",\"cf:pathname\":\"");
  strcat(buffer, n->name);
  strcat(buffer, "\"");
  catlabel("path", n->name);
  strcat(buffer, "}");
  return buffer;
}

char* ifc_to_json(struct ifc_context_struct* n){
  char node_info[1024];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  catnodestart(buffer, n);
  strcat(buffer, ",\"cf:ifc\":\"TODO\"}");
  return buffer;
}

char* prefix_json(){
  return "\"prov\" : \"http://www.w3.org/ns/prov\", \"cf\":\"http://www.camflow.org\"";
}

char* machine_description_json(char* buffer){
  char tmp[64];
  uint32_t machine_id;
  struct utsname machine_info;

  provenance_get_machine_id(&machine_id);
  uname(&machine_info);
  //strcat(buffer, utoa(machine_id, tmp, DECIMAL))

  buffer[0]='\0';
  strcat(buffer, "{\"prefix\":{");
  strcat(buffer, prefix_json());
  strcat(buffer, "}");
  strcat(buffer, ",\"entity\":{");
  strcat(buffer, "\"");
  strcat(buffer, utoa(machine_id, tmp, DECIMAL));
  strcat(buffer, "\":{");
  strcat(buffer, "\"prov:label\":\"[machine] ");
  strcat(buffer, utoa(machine_id, tmp, DECIMAL));
  strcat(buffer, "\",\"cf:camflow\":\"");
  strcat(buffer, CAMFLOW_VERSION_STR);
  strcat(buffer, "\",\"cf:sysname\":\"");
  strcat(buffer, machine_info.sysname);
  strcat(buffer, "\",\"cf:nodename\":\"");
  strcat(buffer, machine_info.nodename);
  strcat(buffer, "\",\"cf:release\":\"");
  strcat(buffer, machine_info.release);
  strcat(buffer, "\",\"cf:version\":\"");
  strcat(buffer, machine_info.version);
  strcat(buffer, "\",\"cf:machine\":\"");
  strcat(buffer, machine_info.machine);
  strcat(buffer, "\"}}}");
  return buffer;
}
