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
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "provenancelib.h"

int provenance_set_enable(bool value){
  int fd = open(PROV_ENABLE_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  if(value)
  {
    write(fd, "1", sizeof(char));
  }else{
    write(fd, "0", sizeof(char));
  }
  close(fd);
  return 0;
}

bool provenance_get_enable( void ){
  int fd = open(PROV_ENABLE_FILE, O_RDONLY);
  char c;
  if(fd<0)
  {
    return false;
  }

  read(fd, &c, sizeof(char));
  close(fd);
  return c!='0';
}

int provenance_set_all(bool value){
  int fd = open(PROV_ALL_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  if(value)
  {
    write(fd, "1", sizeof(char));
  }else{
    write(fd, "0", sizeof(char));
  }
  close(fd);
  return 0;
}

bool provenance_get_all( void ){
  int fd = open(PROV_ALL_FILE, O_RDONLY);
  char c;
  if(fd<0)
  {
    return false;
  }

  read(fd, &c, sizeof(char));
  close(fd);
  return c!='0';
}

int provenance_set_opaque(bool value){
  int fd = open(PROV_OPAQUE_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  if(value)
  {
    write(fd, "1", sizeof(char));
  }else{
    write(fd, "0", sizeof(char));
  }
  close(fd);
  return 0;
}

int provenance_set_tracked(bool value){
  int fd = open(PROV_TRACKED_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  if(value)
  {
    write(fd, "1", sizeof(char));
  }else{
    write(fd, "0", sizeof(char));
  }
  close(fd);
  return 0;
}

int provenance_set_machine_id(uint32_t v){
  int fd = open(PROV_MACHINE_ID_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  write(fd, &v, sizeof(uint32_t));
  close(fd);
  return 0;
}

int provenance_get_machine_id(uint32_t* v){
  int fd = open(PROV_MACHINE_ID_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  read(fd, v, sizeof(uint32_t));
  close(fd);
  return 0;
}

int provenance_disclose_node(struct disc_node_struct* node){
  int rc;
  int fd = open(PROV_NODE_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  rc = write(fd, node, sizeof(struct disc_node_struct));
  close(fd);
  return rc;
}

int provenance_disclose_relation(struct relation_struct* relation){
  int rc;
  int fd = open(PROV_RELATION_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  rc = write(fd, relation, sizeof(struct relation_struct));
  close(fd);
  return rc;
}

int provenance_self(struct task_prov_struct* self){
  int rc;
  int fd = open(PROV_SELF_FILE, O_RDONLY);

  if(fd<0)
  {
    return fd;
  }
  rc = read(fd, self, sizeof(struct task_prov_struct));
  close(fd);
  return rc;
}

bool provenance_is_present(void){
  if(access(PROV_ENABLE_FILE, F_OK)){ // return 0 if file exists.
    return false;
  }
  return true;
}

int provenance_flush(void){
  char tmp = 1;
  int rc;
  int fd = open(PROV_FLUSH_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  rc = write(fd, &tmp, sizeof(char));
  close(fd);
  return rc;
}

int provenance_read_file(const char name[PATH_MAX], struct inode_prov_struct* inode_info){
  struct prov_file_config cfg;
  int rc;
  int fd = open(PROV_FILE_FILE, O_RDONLY);

  if( fd < 0 ){
    return fd;
  }
  realpath(name, cfg.name);

  rc = read(fd, &cfg, sizeof(struct prov_file_config));
  close(fd);
  memcpy(inode_info, &(cfg.prov), sizeof(struct inode_prov_struct));
  return rc;
}

int provenance_track_file(const char name[PATH_MAX], bool track, uint8_t depth){
  struct prov_file_config cfg;
  int rc;
  int fd = open(PROV_FILE_FILE, O_WRONLY);

  if( fd < 0 ){
    return fd;
  }
  realpath(name, cfg.name);
  cfg.op=PROV_SET_TRACKED|PROV_SET_PROPAGATE;
  if(track){
    cfg.prov.node_kern.tracked=NODE_TRACKED;
    cfg.prov.node_kern.propagate=depth;
  }else{
    cfg.prov.node_kern.tracked=NODE_NOT_TRACKED;
    cfg.prov.node_kern.propagate=0;
  }

  rc = write(fd, &cfg, sizeof(struct prov_file_config));
  close(fd);
  return rc;
}

int provenance_opaque_file(const char name[PATH_MAX], bool opaque){
  struct prov_file_config cfg;
  int rc;
  int fd = open(PROV_FILE_FILE, O_WRONLY);

  if( fd < 0 ){
    return fd;
  }
  realpath(name, cfg.name);
  cfg.op=PROV_SET_OPAQUE;
  if(opaque){
    cfg.prov.node_kern.opaque=NODE_OPAQUE;
  }else{
    cfg.prov.node_kern.opaque=NODE_NOT_OPAQUE;
  }

  rc = write(fd, &cfg, sizeof(struct prov_file_config));
  close(fd);
  return rc;
}
