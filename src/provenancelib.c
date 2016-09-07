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

static inline int __set_boolean(bool value, const char* name){
  int fd = open(name, O_WRONLY);

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

static inline bool __get_boolean(const char* name){
  int fd = open(name, O_RDONLY);
  char c;
  if(fd<0)
  {
    return false;
  }

  read(fd, &c, sizeof(char));
  close(fd);
  return c!='0';
}

#define declare_set_boolean_fcn( fcn_name, file_name ) int fcn_name (bool value ) { return __set_boolean(value, file_name);}
#define declare_get_boolean_fcn( fcn_name, file_name ) bool fcn_name ( void ) { return __get_boolean(file_name);}

declare_set_boolean_fcn(provenance_set_enable, PROV_ENABLE_FILE);
declare_get_boolean_fcn(provenance_get_enable, PROV_ENABLE_FILE);

declare_set_boolean_fcn(provenance_set_all, PROV_ALL_FILE);
declare_get_boolean_fcn(provenance_get_all, PROV_ALL_FILE);

declare_set_boolean_fcn(provenance_set_tracked, PROV_TRACKED_FILE);
declare_get_boolean_fcn(provenance_get_tracked, PROV_TRACKED_FILE);

declare_set_boolean_fcn(provenance_set_opaque, PROV_OPAQUE_FILE);
declare_get_boolean_fcn(provenance_get_opaque, PROV_OPAQUE_FILE);

declare_set_boolean_fcn(provenance_set_propagate, PROV_PROPAGATE_FILE);
declare_get_boolean_fcn(provenance_get_propagate, PROV_PROPAGATE_FILE);

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

int provenance_read_file(const char name[PATH_MAX], prov_msg_t* inode_info){
  struct prov_file_config cfg;
  int rc;
  int fd = open(PROV_FILE_FILE, O_RDONLY);

  if( fd < 0 ){
    return fd;
  }
  realpath(name, cfg.name);

  rc = read(fd, &cfg, sizeof(struct prov_file_config));
  close(fd);
  memcpy(inode_info, &(cfg.prov), sizeof(prov_msg_t));
  return rc;
}

#define declare_set_file_fcn(fcn_name, element, operation) int fcn_name (const char name[PATH_MAX], bool track){\
    struct prov_file_config cfg;\
    int rc;\
    int fd = open(PROV_FILE_FILE, O_WRONLY);\
    if( fd < 0 ){\
      return fd;\
    }\
    realpath(name, cfg.name);\
    cfg.op=operation;\
    if(track){\
      prov_set_flag(&cfg.prov, element);\
    }else{\
      prov_clear_flag(&cfg.prov, element);\
    }\
    rc = write(fd, &cfg, sizeof(struct prov_file_config));\
    close(fd);\
    return rc;\
  }

declare_set_file_fcn(provenance_track_file, TRACKED_BIT, PROV_SET_TRACKED);
declare_set_file_fcn(provenance_opaque_file, OPAQUE_BIT, PROV_SET_OPAQUE);
declare_set_file_fcn(provenance_propagate_file, PROPAGATE_BIT, PROV_SET_PROPAGATE);
