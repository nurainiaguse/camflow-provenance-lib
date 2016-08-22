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
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include "provenancelib.h"
#include "provenancefilter.h"

int provenance_add_node_filter( uint32_t filter ){
  struct prov_filter f;
  int fd = open(PROV_NODE_FILTER_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  f.add=1;

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

int provenance_remove_node_filter( uint32_t filter ){
  struct prov_filter f;
  int fd = open(PROV_NODE_FILTER_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  f.add=0;

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

int provenance_get_node_filter( uint32_t* filter ){
  int fd = open(PROV_NODE_FILTER_FILE, O_RDONLY);
  int err=0;
  if(fd<0)
  {
    return fd;
  }

  read(fd, filter, sizeof(uint32_t));
  close(fd);
  return 0;
}

int provenance_add_propagate_node_filter( uint32_t filter ){
  struct prov_filter f;
  int fd = open(PROV_PROPAGATE_NODE_FILTER_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  f.add=1;

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

int provenance_remove_propagate_node_filter( uint32_t filter ){
  struct prov_filter f;
  int fd = open(PROV_PROPAGATE_NODE_FILTER_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  f.add=0;

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

int provenance_get_propagate_node_filter( uint32_t* filter ){
  int fd = open(PROV_PROPAGATE_NODE_FILTER_FILE, O_RDONLY);
  int err=0;
  if(fd<0)
  {
    return fd;
  }

  read(fd, filter, sizeof(uint32_t));
  close(fd);
  return 0;
}

int provenance_add_relation_filter( uint32_t filter ){
  struct prov_filter f;
  int fd = open(PROV_RELATION_FILTER_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  f.add=1;

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

int provenance_remove_relation_filter( uint32_t filter ){
  struct prov_filter f;
  int fd = open(PROV_RELATION_FILTER_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  f.add=0;

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

int provenance_get_relation_filter( uint32_t* filter ){
  int fd = open(PROV_RELATION_FILTER_FILE, O_RDONLY);
  int err=0;
  if(fd<0)
  {
    return fd;
  }

  read(fd, filter, sizeof(uint32_t));
  close(fd);
  return 0;
}


int provenance_add_propagate_relation_filter( uint32_t filter ){
  struct prov_filter f;
  int fd = open(PROV_PROPAGATE_RELATION_FILTER_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  f.add=1;

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

int provenance_remove_propagate_relation_filter( uint32_t filter ){
  struct prov_filter f;
  int fd = open(PROV_PROPAGATE_RELATION_FILTER_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  f.add=0;

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

int provenance_get_propagate_relation_filter( uint32_t* filter ){
  int fd = open(PROV_PROPAGATE_RELATION_FILTER_FILE, O_RDONLY);
  int err=0;
  if(fd<0)
  {
    return fd;
  }

  read(fd, filter, sizeof(uint32_t));
  close(fd);
  return 0;
}
