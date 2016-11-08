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

#define MAX_PROVJSON_BUFFER_EXP     12
#define MAX_PROVJSON_BUFFER_LENGTH  ((1 << MAX_PROVJSON_BUFFER_EXP)*sizeof(uint8_t))

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

static char date[256];
pthread_rwlock_t  date_lock = PTHREAD_RWLOCK_INITIALIZER;

// ideally should be derived from jiffies
static void update_time( void ){
  struct tm* tm;
  struct timeval tv;

  pthread_rwlock_wrlock(&date_lock);
  gettimeofday(&tv, NULL);
  tm = gmtime(&tv.tv_sec);
  strftime(date, 30,"%Y:%m:%dT%H:%M:%S", tm);
  pthread_rwlock_unlock(&date_lock);
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

static char* activity;
static char* agent;
static char* entity;
static char* relation;
static char* used;
static char* generated;
static char* informed;
static char* derived;
static char* message;

void init_buffers(void){
  activity = (char*)malloc(MAX_PROVJSON_BUFFER_LENGTH*sizeof(char));
  activity[0]='\0';
  agent = (char*)malloc(MAX_PROVJSON_BUFFER_LENGTH*sizeof(char));
  agent[0]='\0';
  entity = (char*)malloc(MAX_PROVJSON_BUFFER_LENGTH*sizeof(char));
  entity[0]='\0';
  relation = (char*)malloc(MAX_PROVJSON_BUFFER_LENGTH*sizeof(char));
  relation[0]='\0';
  used = (char*)malloc(MAX_PROVJSON_BUFFER_LENGTH*sizeof(char));
  used[0]='\0';
  generated = (char*)malloc(MAX_PROVJSON_BUFFER_LENGTH*sizeof(char));
  generated[0]='\0';
  informed = (char*)malloc(MAX_PROVJSON_BUFFER_LENGTH*sizeof(char));
  informed[0]='\0';
  derived = (char*)malloc(MAX_PROVJSON_BUFFER_LENGTH*sizeof(char));
  derived[0]='\0';
  message = (char*)malloc(MAX_PROVJSON_BUFFER_LENGTH*sizeof(char));
  message[0]='\0';
}

bool writing_out = false;

static void (*print_json)(char* json);

int disclose_node_ProvJSON(uint64_t type, const char* content, prov_identifier_t* identifier){
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

int disclose_relation_ProvJSON(uint64_t type, prov_identifier_t* sender, prov_identifier_t* receiver){
  struct relation_struct relation;
  relation.identifier.relation_id.type=type;
  relation.allowed=true;
  memcpy(&relation.snd, sender, sizeof(prov_identifier_t));
  memcpy(&relation.rcv, receiver, sizeof(prov_identifier_t));
  return provenance_disclose_relation(&relation);
}

void set_ProvJSON_callback( void (*fcn)(char* json) ){
  init_buffers();
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
    update_time(); // we update the time
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

static inline void __init_json_entry(char* buffer, const char* id)
{
  buffer[0]='\0';
  strcat(buffer, "\"");
  strcat(buffer, id);
  strcat(buffer, "\":{");
}

static inline void __add_attribute(char* buffer, const char* name, bool comma){
  if(comma){
    strcat(buffer, ",\"");
  }else{
    strcat(buffer, "\"");
  }
  strcat(buffer, name);
  strcat(buffer, "\":");
}

static inline void __add_uint32_attribute(char* buffer, const char* name, const uint32_t value, bool comma){
  char tmp[32];
  __add_attribute(buffer, name, comma);
  strcat(buffer, utoa(value, tmp, DECIMAL));
}


static inline void __add_int32_attribute(char* buffer, const char* name, const int32_t value, bool comma){
  char tmp[32];
  __add_attribute(buffer, name, comma);
  strcat(buffer, itoa(value, tmp, DECIMAL));
}

static inline void __add_uint32hex_attribute(char* buffer, const char* name, const uint32_t value, bool comma){
  char tmp[32];
  __add_attribute(buffer, name, comma);
  strcat(buffer, "\"0x");
  strcat(buffer, utoa(value, tmp, HEX));
  strcat(buffer, "\"");
}

static inline void __add_uint64_attribute(char* buffer, const char* name, const uint64_t value, bool comma){
  char tmp[64];
  __add_attribute(buffer, name, comma);
  strcat(buffer, "\"");
  strcat(buffer, ulltoa(value, tmp, DECIMAL));
  strcat(buffer, "\"");
}

static inline void __add_uint64hex_attribute(char* buffer, const char* name, const uint64_t value, bool comma){
  char tmp[64];
  __add_attribute(buffer, name, comma);
  strcat(buffer, "\"");
  strcat(buffer, ulltoa(value, tmp, HEX));
  strcat(buffer, "\"");
}

static inline void __add_int64_attribute(char* buffer, const char* name, const int64_t value, bool comma){
  char tmp[64];
  __add_attribute(buffer, name, comma);
  strcat(buffer, "\"");
  strcat(buffer, lltoa(value, tmp, DECIMAL));
  strcat(buffer, "\"");
}

static inline void __add_string_attribute(char* buffer, const char* name, const char* value, bool comma){
  char tmp[64];
  if(value[0]=='\0'){ // value is not set
    return;
  }
  __add_attribute(buffer, name, comma);
  strcat(buffer, "\"");
  strcat(buffer, value);
  strcat(buffer, "\"");
}

static inline void __add_json_attribute(char* buffer, const char* name, const char* value, bool comma){
  char tmp[64];
  __add_attribute(buffer, name, comma);
  strcat(buffer, value);
}

static inline void __add_date_attribute(char* buffer, bool comma){
  __add_attribute(buffer, "cf:date", comma);
  strcat(buffer, "\"");
  pthread_rwlock_rdlock(&date_lock);
  strcat(buffer, date);
  pthread_rwlock_unlock(&date_lock);
  strcat(buffer, "\"");
}

static inline void __add_label_attribute(char* buffer, const char* type, const char* text, bool comma){
  __add_attribute(buffer, "prov:label", comma);
  if(type!=NULL){
    strcat(buffer, "\"[");
    strcat(buffer, type);
    strcat(buffer, "] ");
  }else{
    strcat(buffer, "\"");
  }
  strcat(buffer, text);
  strcat(buffer, "\"");
}

static inline char* __format_ipv4(char* buffer, uint32_t ip, uint32_t port){
    char tmp[8];
    unsigned char bytes[4];
    ip = htonl(ip);
    port = htons(port);
    buffer[0]='\0';
    strcat(buffer, uint32_to_ipv4str(ip));
    strcat(buffer, ":");
    strcat(buffer, utoa(port, tmp, DECIMAL));
    return buffer;
}

static inline void __add_ipv4_attribute(char* buffer, const char* name, const uint32_t ip, const uint32_t port, bool comma){
  char tmp[64];
  __add_attribute(buffer, name, comma);
  strcat(buffer, "\"");
  strcat(buffer, __format_ipv4(tmp, ip, port));
  strcat(buffer, "\"");
}

static inline void __close_json_entry(char* buffer)
{
  strcat(buffer, "}");
}

static void prov_prep_taint(const uint8_t bloom[PROV_N_BYTES]){
  struct taint_entry* tmp = &taint_list;
  bool first=true;
  if(prov_bloom_empty(bloom)){
    taint[0]='\0';
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

static inline void __node_identifier(char* buffer, const struct node_identifier* n){
  __add_uint64_attribute(buffer, "cf:id", n->id, false);
  __add_string_attribute(buffer, "cf:type", node_str(n->type), true);
  __add_uint32_attribute(buffer, "cf:boot_id", n->boot_id, true);
  __add_uint32_attribute(buffer, "cf:machine_id", n->machine_id, true);
  __add_uint32_attribute(buffer, "cf:version", n->version, true);
}

static inline void __node_start(char* buffer,
                                const char* id,
                                const struct node_identifier* n,
                                const char* taint,
                                uint64_t jiffies){
  __init_json_entry(buffer, id);
  __node_identifier(buffer, n);
  __add_date_attribute(buffer, true);
  __add_string_attribute(buffer, "cf:taint", taint, true);
  __add_uint64_attribute(buffer, "cf:jiffies", jiffies, true);
}

static inline void __relation_identifier(char* buffer, const struct relation_identifier* e){
  __add_uint64_attribute(buffer, "cf:id", e->id, false);
  __add_string_attribute(buffer, "cf:type", relation_str(e->type), true);
  __add_uint32_attribute(buffer, "cf:boot_id", e->boot_id, true);
  __add_uint32_attribute(buffer, "cf:machine_id", e->machine_id, true);
}

static char* bool_str[] = {"false", "true"};

static char* __relation_to_json(struct relation_struct* e, const char* snd, const char* rcv){
  RELATION_PREP_IDs(e);
  prov_prep_taint(e->taint);
  __init_json_entry(buffer, id);
  __relation_identifier(buffer, &(e->identifier.relation_id));
  __add_date_attribute(buffer, true);
  __add_string_attribute(buffer, "cf:taint", taint, true);
  __add_uint64_attribute(buffer, "cf:jiffies", e->jiffies, true);
  __add_label_attribute(buffer, NULL, relation_str(e->identifier.relation_id.type), true);
  __add_string_attribute(buffer, "cf:allowed", bool_str[e->allowed], true);
  __add_string_attribute(buffer, snd, sender, true);
  __add_string_attribute(buffer, rcv, receiver, true);
  if(e->set==FILE_INFO_SET){ // if file related info were set
    __add_int64_attribute(buffer, "cf:offset", e->offset, true); // just offset for now
  }
  __close_json_entry(buffer);
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

char* disc_to_json(struct disc_node_struct* n){
  DISC_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_string_attribute(buffer, "cf:hasParent", parent_id, true);
  if(n->length > 0){
    strcat(buffer, ",");
    strcat(buffer, n->content);
  }
  __close_json_entry(buffer);
  return buffer;
}

char* task_to_json(struct task_prov_struct* n){
  char tmp[33];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_uint32_attribute(buffer, "cf:uid", n->uid, true);
  __add_uint32_attribute(buffer, "cf:gid", n->gid, true);
  __add_uint32_attribute(buffer, "cf:pid", n->pid, true);
  __add_uint32_attribute(buffer, "cf:vpid", n->vpid, true);
  __add_label_attribute(buffer, "task", utoa(n->identifier.node_id.version, tmp, DECIMAL), true);
  __close_json_entry(buffer);
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


char* inode_to_json(struct inode_prov_struct* n){
  char uuid[UUID_STR_SIZE];
  char tmp[65];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_uint32_attribute(buffer, "cf:uid", n->uid, true);
  __add_uint32_attribute(buffer, "cf:gid", n->gid, true);
  __add_string_attribute(buffer, "prov:type", node_str(n->identifier.node_id.type), true);
  __add_uint32hex_attribute(buffer, "cf:mode", n->mode, true);
  __add_string_attribute(buffer, "cf:uuid", uuid_to_str(n->sb_uuid, uuid, UUID_STR_SIZE), true);
  __add_label_attribute(buffer, node_str(n->identifier.node_id.type), utoa(n->identifier.node_id.version, tmp, DECIMAL), true);
  __close_json_entry(buffer);
  return buffer;
}

char* sb_to_json(struct sb_struct* n){
  char uuid[UUID_STR_SIZE];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_string_attribute(buffer, "cf:uuid", uuid_to_str(n->uuid, uuid, UUID_STR_SIZE), true);
  __close_json_entry(buffer);
  return buffer;
}

char* msg_to_json(struct msg_msg_struct* n){
  char tmp[65];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_uint64_attribute(buffer, "cf:type", n->type, true);
  __close_json_entry(buffer);
  return buffer;
}

char* shm_to_json(struct shm_struct* n){
  char tmp[33];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_uint32hex_attribute(buffer, "cf:mode", n->mode, true);
  __close_json_entry(buffer);
  return buffer;
}

char* packet_to_json(struct pck_struct* p){
  char tmp[256];
  PACKET_PREP_IDs(p);
  prov_prep_taint(p->taint);
  __init_json_entry(buffer, id);
  __add_uint32_attribute(buffer, "cf:id", p->identifier.packet_id.id, false);
  __add_uint32_attribute(buffer, "cf:seq", p->identifier.packet_id.seq, true);
  __add_ipv4_attribute(buffer, "cf:sender", p->identifier.packet_id.snd_ip, p->identifier.packet_id.snd_port, true);
  __add_ipv4_attribute(buffer, "cf:receiver", p->identifier.packet_id.rcv_ip, p->identifier.packet_id.rcv_port, true);
  __add_string_attribute(buffer, "cf:taint", taint, true);
  __add_uint64_attribute(buffer, "cf:jiffies", p->jiffies, true);
  strcat(buffer, ",\"prov:label\":\"[packet] ");
  strcat(buffer, __format_ipv4(tmp, p->identifier.packet_id.snd_ip, p->identifier.packet_id.snd_port));
  strcat(buffer, "->");
  strcat(buffer, __format_ipv4(tmp, p->identifier.packet_id.rcv_ip, p->identifier.packet_id.rcv_port));
  strcat(buffer, " (");
  strcat(buffer, utoa(p->identifier.packet_id.id, tmp, DECIMAL));
  strcat(buffer, ")\"");
  __close_json_entry(buffer);
  return buffer;
}

char* str_msg_to_json(struct str_struct* n){
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_string_attribute(buffer, "cf:message", n->str, true);
  __close_json_entry(buffer);
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
  char addr_info[PATH_MAX+1024];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_json_attribute(buffer, "cf:address", sockaddr_to_json(addr_info, &n->addr, n->length), true);
  __add_label_attribute(buffer, "address", sockaddr_to_label(addr_info, &n->addr, n->length), true);
  __close_json_entry(buffer);
  return buffer;
}

char* pathname_to_json(struct file_name_struct* n){
  char node_info[1024];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_string_attribute(buffer, "cf:pathname", n->name, true);
  __add_label_attribute(buffer, "path", n->name, true);
  __close_json_entry(buffer);
  return buffer;
}

char* ifc_to_json(struct ifc_context_struct* n){
  char node_info[1024];
  NODE_PREP_IDs(n);
  prov_prep_taint(n->taint);
  __node_start(buffer, id, &(n->identifier.node_id), taint, n->jiffies);
  __add_string_attribute(buffer, "cf:pathname", "TODO", true);
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
