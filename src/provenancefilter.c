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

static inline int __provenance_change_filter( bool add, const char* file, uint32_t filter ){
  struct prov_filter f;
  int fd = open(file, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  if(add){
    f.add=1;
  }else{
    f.add=0;
  }

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

static inline int __provenance_get_filter( const char* file, uint32_t* filter ){
  int fd = open(file, O_RDONLY);
  if(fd<0)
  {
    return fd;
  }

  read(fd, filter, sizeof(uint32_t));
  close(fd);
  return 0;
}

#define define_change_filter_fcn(fcn_name, add, file) int fcn_name ( uint32_t filter ){return __provenance_change_filter(add, file, filter);}
#define define_get_filter_fcn(fcn_name, file) int fcn_name ( uint32_t* filter ){ return __provenance_get_filter( file, filter );}

// node filter
define_change_filter_fcn(provenance_add_node_filter, true, PROV_NODE_FILTER_FILE);
define_change_filter_fcn(provenance_remove_node_filter, false, PROV_NODE_FILTER_FILE);
define_get_filter_fcn(provenance_get_node_filter, PROV_NODE_FILTER_FILE);

// propagate node filter
define_change_filter_fcn(provenance_add_propagate_node_filter, true, PROV_PROPAGATE_NODE_FILTER_FILE);
define_change_filter_fcn(provenance_remove_propagate_node_filter, false, PROV_PROPAGATE_NODE_FILTER_FILE);
define_get_filter_fcn(provenance_get_propagate_node_filter, PROV_PROPAGATE_NODE_FILTER_FILE);

// relation filter
define_change_filter_fcn(provenance_add_relation_filter, true, PROV_RELATION_FILTER_FILE);
define_change_filter_fcn(provenance_remove_relation_filter, false, PROV_RELATION_FILTER_FILE);
define_get_filter_fcn(provenance_get_relation_filter, PROV_RELATION_FILTER_FILE);

// propagate relation filter
define_change_filter_fcn(provenance_add_propagate_relation_filter, true, PROV_PROPAGATE_RELATION_FILTER_FILE);
define_change_filter_fcn(provenance_remove_propagate_relation_filter, false, PROV_PROPAGATE_RELATION_FILTER_FILE);
define_get_filter_fcn(provenance_get_propagate_relation_filter, PROV_PROPAGATE_RELATION_FILTER_FILE);
