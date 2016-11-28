/*
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

#include "simplog.h"
#include "provenancelib.h"
#include "provenanceutils.h"
#include "provenancePovJSON.h"

#define	LOG_FILE "/tmp/audit.log"
#define gettid() syscall(SYS_gettid)

static pthread_mutex_t l_log =  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

void _init_logs( void ){
  simplog.setLogFile(LOG_FILE);
  simplog.setLineWrap(false);
  simplog.setLogSilentMode(true);
  simplog.setLogDebugLevel(SIMPLOG_VERBOSE);
}

void init( void ){
  pid_t tid = gettid();
  pthread_mutex_lock(&l_log);
  simplog.writeLog(SIMPLOG_INFO, "audit writer thread, tid:%ld", tid);
  pthread_mutex_unlock(&l_log);
}


void log_str(struct str_struct* data){
  append_message(str_msg_to_json(data));
}

void log_unknown_relation(struct relation_struct* relation){
  append_relation(relation_to_json(relation));
}

void log_derived(struct relation_struct* relation){
  append_derived(derived_to_json(relation));
}

void log_generated(struct relation_struct* relation){
  append_generated(generated_to_json(relation));
}

void log_used(struct relation_struct* relation){
  append_used(used_to_json(relation));
}

void log_informed(struct relation_struct* relation){
  append_informed(informed_to_json(relation));
}

void log_task(struct task_prov_struct* task){
  append_activity(task_to_json(task));
}

void log_inode(struct inode_prov_struct* inode){
  append_entity(inode_to_json(inode));
}

void log_disc(struct disc_node_struct* node){
  switch(node->identifier.node_id.type){
    case ACT_DISC:
      append_activity(disc_to_json(node));
      break;
    case AGT_DISC:
      append_agent(disc_to_json(node));
      break;
    case ENT_DISC:
    default:
      append_entity(disc_to_json(node));
      break;
  }
}

void log_msg(struct msg_msg_struct* msg){
  append_entity(msg_to_json(msg));
}

void log_shm(struct shm_struct* shm){
  append_entity(shm_to_json(shm));
}

void log_packet(struct pck_struct* pck){
  append_entity(packet_to_json(pck));
}

void log_address(struct address_struct* address){
  append_entity(addr_to_json(address));
}

void log_file_name(struct file_name_struct* f_name){
  append_entity(pathname_to_json(f_name));
}

void log_ifc(struct ifc_context_struct* ifc){
  append_entity(ifc_to_json(ifc));
}

void log_iattr(struct iattr_prov_struct* iattr){
  append_entity(iattr_to_json(iattr));
}

void log_xattr(struct xattr_prov_struct* xattr){
  append_entity(xattr_to_json(xattr));
}

bool filter(prov_msg_t* msg){
  return false;
}

bool long_filter(long_prov_msg_t* msg){
  return false;
}

void log_error(char* err_msg){
  pthread_mutex_lock(&l_log);
  simplog.writeLog(SIMPLOG_ERROR,  err_msg);
  pthread_mutex_unlock(&l_log);
}

struct provenance_ops ops = {
  .init=init,
  .filter=filter,
  .long_filter=long_filter,
  .log_unknown_relation=log_unknown_relation,
  .log_derived=log_derived,
  .log_generated=log_generated,
  .log_used=log_used,
  .log_informed=log_informed,
  .log_task=log_task,
  .log_inode=log_inode,
  .log_str=log_str,
  .log_disc=log_disc,
  .log_msg=log_msg,
  .log_shm=log_shm,
  .log_packet=log_packet,
  .log_address=log_address,
  .log_file_name=log_file_name,
  .log_ifc=log_ifc,
  .log_iattr=log_iattr,
  .log_xattr=log_xattr,
  .log_error=log_error
};

void print_json(char* json){
    pthread_mutex_lock(&l_log);
    simplog.writeLog(SIMPLOG_INFO,  json);
    pthread_mutex_unlock(&l_log);
}

int main(void){
  int rc;
  char json[4096];
	_init_logs();
  simplog.writeLog(SIMPLOG_INFO, "audit service pid: %ld", getpid());
  set_ProvJSON_callback(print_json);
  rc = provenance_register(&ops);
  if(rc<0){
    simplog.writeLog(SIMPLOG_ERROR, "Failed registering audit operation (%d).", rc);
    exit(rc);
  }
  simplog.writeLog(SIMPLOG_INFO, machine_description_json(json));

  while(1){
    sleep(1);
    flush_json();
  }
  provenance_stop();
  return 0;
}
