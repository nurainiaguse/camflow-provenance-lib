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

void write_to_log(const char* fmt, ...){
  char tmp[10192];
	va_list args;
	va_start(args, fmt);
  vsprintf(tmp, fmt, args);
	va_end(args);
  pthread_mutex_lock(&mut);
  simplog.writeLog(SIMPLOG_INFO, tmp);
  pthread_mutex_unlock(&mut);
}

void init( void ){
  pid_t tid = gettid();
  write_to_log("audit writer thread, tid:%ld", tid);
}

static __thread char buffer[6144]; // check the size

void log_str(struct str_struct* data){
  write_to_log("%s", str_msg_to_json(buffer, data));
}

void log_link(struct link_struct* link){
  write_to_log("%s", link_to_json(buffer, link));
}

void log_unlink(struct unlink_struct* unlink){
  write_to_log("%s", unlink_to_json(buffer, unlink));
}

void log_edge(struct edge_struct* edge){
    write_to_log("%s", edge_to_json(buffer, edge));
}

void log_task(struct task_prov_struct* task){
  write_to_log("%s", task_to_json(buffer, task));
}

void log_inode(struct inode_prov_struct* inode){
    write_to_log("%s", inode_to_json(buffer, inode));
}

void log_disc(struct disc_node_struct* node){
    write_to_log("%s", disc_to_json(buffer, node));
}

void log_msg(struct msg_msg_struct* msg){
    write_to_log("%s", msg_to_json(buffer, msg));
}

void log_shm(struct shm_struct* shm){
    write_to_log("%s", shm_to_json(buffer, shm));
}


void log_sock(struct sock_struct* sock){
    write_to_log("%s", sock_to_json(buffer, sock));
}

void log_address(struct address_struct* address){
    write_to_log("%s", addr_to_json(buffer, address));
}

void log_file_name(struct file_name_struct* f_name){
    write_to_log("%s", pathname_to_json(buffer, f_name));
}

void log_ifc(struct ifc_context_struct* ifc){
    write_to_log("%s", ifc_to_json(buffer, ifc));
}

struct provenance_ops ops = {
  .init=init,
  .log_edge=log_edge,
  .log_task=log_task,
  .log_inode=log_inode,
  .log_str=log_str,
  .log_link=log_link,
  .log_unlink=log_unlink,
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
  simplog.writeLog(SIMPLOG_INFO, "audit process pid: %d", getpid());
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
