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

static inline int __provenance_change_filter( bool add, const char* file, uint64_t filter, uint64_t mask ){
  struct prov_filter f;
  int fd = open(file, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  f.filter=filter;
  f.mask=mask;
  if(add){
    f.add=1;
  }else{
    f.add=0;
  }

  write(fd, &f, sizeof(struct prov_filter));
  close(fd);
  return 0;
}

static inline int __provenance_get_filter( const char* file, uint64_t* filter ){
  int fd = open(file, O_RDONLY);
  if(fd<0)
  {
    return fd;
  }

  read(fd, filter, sizeof(uint64_t));
  close(fd);
  return 0;
}

#define declare_change_filter_fcn(fcn_name, add, file, mask) int fcn_name ( uint64_t filter ){return __provenance_change_filter(add, file, filter, mask);}
#define declare_get_filter_fcn(fcn_name, file) int fcn_name ( uint64_t* filter ){ return __provenance_get_filter( file, filter );}
#define declare_reset_filter_fcn(fcn_name, file) int fcn_name ( void ){return __provenance_change_filter(false, file, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);}


// node filter
declare_change_filter_fcn(provenance_add_node_filter, true, PROV_NODE_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_node_filter, false, PROV_NODE_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_node_filter, PROV_NODE_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_node_filter, PROV_NODE_FILTER_FILE);

// propagate node filter
declare_change_filter_fcn(provenance_add_propagate_node_filter, true, PROV_PROPAGATE_NODE_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_propagate_node_filter, false, PROV_PROPAGATE_NODE_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_propagate_node_filter, PROV_PROPAGATE_NODE_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_propagate_node_filter, PROV_PROPAGATE_NODE_FILTER_FILE);

// relation filter
declare_change_filter_fcn(provenance_add_relation_filter, true, PROV_RELATION_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_relation_filter, false, PROV_RELATION_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_relation_filter, PROV_RELATION_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_relation_filter, PROV_RELATION_FILTER_FILE);

// propagate relation filter
declare_change_filter_fcn(provenance_add_propagate_relation_filter, true, PROV_PROPAGATE_RELATION_FILTER_FILE, SUBTYPE_MASK);
declare_change_filter_fcn(provenance_remove_propagate_relation_filter, false, PROV_PROPAGATE_RELATION_FILTER_FILE, SUBTYPE_MASK);
declare_get_filter_fcn(provenance_get_propagate_relation_filter, PROV_PROPAGATE_RELATION_FILTER_FILE);
declare_reset_filter_fcn(provenance_reset_propagate_relation_filter, PROV_PROPAGATE_RELATION_FILTER_FILE);
