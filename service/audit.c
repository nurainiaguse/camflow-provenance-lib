/*
* CamFlow userspace audit example
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

#include "simplog.h"
#include "provenancelib.h"
#include "provenancePovJSON.h"

#define	LOG_FILE "/tmp/audit.log"
#define gettid() syscall(SYS_gettid)

void _init_logs( void ){
  simplog.setLogFile(LOG_FILE);
  simplog.setLineWrap(false);
  simplog.setLogSilentMode(true);
  simplog.setLogDebugLevel(SIMPLOG_VERBOSE);
}

void init( void ){
  pid_t tid = gettid();
  simplog.writeLog(SIMPLOG_INFO, "audit writer thread, tid:%ld", tid);
}


void log_str(struct str_struct* data){
  append_message(str_msg_to_json(data));
}

void log_edge(struct edge_struct* edge){
  append_edge(edge_to_json(edge));
}

void log_task(struct task_prov_struct* task){
  append_activity(task_to_json(task));
}

void log_inode(struct inode_prov_struct* inode){
  append_entity(inode_to_json(inode));
}

void log_disc(struct disc_node_struct* node){
  append_entity(disc_to_json(node));
}

void log_msg(struct msg_msg_struct* msg){
  append_entity(msg_to_json(msg));
}

void log_shm(struct shm_struct* shm){
  append_entity(shm_to_json(shm));
}


void log_sock(struct sock_struct* sock){
  append_entity(sock_to_json(sock));
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

struct provenance_ops ops = {
  .init=init,
  .log_edge=log_edge,
  .log_task=log_task,
  .log_inode=log_inode,
  .log_str=log_str,
  .log_disc=log_disc,
  .log_msg=log_msg,
  .log_shm=log_shm,
  .log_sock=log_sock,
  .log_address=log_address,
  .log_file_name=log_file_name,
  .log_ifc=log_ifc
};

void print_json(char* json){
  if(strlen(json)>100){
    simplog.writeLog(SIMPLOG_INFO,  json);
  }
}

int main(void){
  int rc;
  //hostid = gethostid();
	_init_logs();
  simplog.writeLog(SIMPLOG_INFO, "audit process pid: %ld", getpid());
  rc = provenance_register(&ops);
  if(rc){
    simplog.writeLog(SIMPLOG_ERROR, "Failed registering audit operation.");
    exit(rc);
  }
  set_ProvJSON_callback(print_json);
  while(1){
    sleep(5);
    flush_json();
  }
  provenance_stop();
  return 0;
}
