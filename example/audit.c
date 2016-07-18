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
#include <pthread.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>

#include "simplog.h"
#include "provenancelib.h"

#define	LOG_FILE "/tmp/audit.log"
#define gettid() syscall(SYS_gettid)

void _init_logs( void ){
  simplog.setLogFile(LOG_FILE);
  simplog.setLineWrap(false);
  simplog.setLogSilentMode(true);
  simplog.setLogDebugLevel(SIMPLOG_VERBOSE);
}

pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

static __thread char buffer[10192]; // check the size

void init( void ){
  pid_t tid = gettid();
  simplog.writeLog(SIMPLOG_INFO, "audit writer thread, tid:%ld", tid);
}


void log_str(struct str_struct* data){
  simplog.writeLog(SIMPLOG_INFO, str_msg_to_json(buffer, data));
}

void log_edge(struct edge_struct* edge){
  simplog.writeLog(SIMPLOG_INFO, edge_to_json(buffer, edge));
}

void log_task(struct task_prov_struct* task){
  simplog.writeLog(SIMPLOG_INFO, task_to_json(buffer, task));
}

void log_inode(struct inode_prov_struct* inode){
  simplog.writeLog(SIMPLOG_INFO, inode_to_json(buffer, inode));
}

void log_disc(struct disc_node_struct* node){
  simplog.writeLog(SIMPLOG_INFO, disc_to_json(buffer, node));
}

void log_msg(struct msg_msg_struct* msg){
  simplog.writeLog(SIMPLOG_INFO, msg_to_json(buffer, msg));
}

void log_shm(struct shm_struct* shm){
  simplog.writeLog(SIMPLOG_INFO, shm_to_json(buffer, shm));
}


void log_sock(struct sock_struct* sock){
  simplog.writeLog(SIMPLOG_INFO, sock_to_json(buffer, sock));
}

void log_address(struct address_struct* address){
  simplog.writeLog(SIMPLOG_INFO, addr_to_json(buffer, address));
}

void log_file_name(struct file_name_struct* f_name){
  simplog.writeLog(SIMPLOG_INFO, pathname_to_json(buffer, f_name));
}

void log_ifc(struct ifc_context_struct* ifc){
  simplog.writeLog(SIMPLOG_INFO, ifc_to_json(buffer, ifc));
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
  sleep(2);
  while(1) sleep(60);
  provenance_stop();
  return 0;
}
