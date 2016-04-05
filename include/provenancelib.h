/*
*
* provenancelib.h
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
#ifndef __PROVENANCELIB_H
#define __PROVENANCELIB_H


#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/provenance.h>


static char* edge_str[]={"data", "create", "pass", "change", "mmap", "attach", "associate", "bind", "connect", "listen", "accept", "open", "parent", "version", "unknown"};

struct provenance_ops{
  void (*init)(void);
  void (*log_edge)(struct edge_struct*);
  void (*log_task)(struct task_prov_struct*);
  void (*log_inode)(struct inode_prov_struct*);
  void (*log_str)(struct str_struct*);
  void (*log_link)(struct link_struct*);
  void (*log_unlink)(struct unlink_struct*);
  void (*log_disc)(struct disc_node_struct*);
  void (*log_msg)(struct msg_msg_struct*);
  void (*log_shm)(struct shm_struct*);
  void (*log_sock)(struct sock_struct*);
  void (*log_address)(struct address_struct*);
  void (*log_file_name)(struct file_name_struct*);
  void (*log_ifc)(struct ifc_context_struct*);
};

/* provenance usher functions */

/*
* @ops structure containing audit callbacks
* start and register callback. Note that there is no concurrency guarantee made.
* The application developper is expected to deal with concurrency issue.
*/
int provenance_register(struct provenance_ops* ops);

/*
* shutdown tightly the things that are running behind the scene.
*/
void provenance_stop(void);

/* security file manipulation */

/*
* @v boolean value
* enable or disable provenance data capture depending on the value of v. Will
* fail if the current process is not root.
*/
int provenance_set_enable(bool v);

/*
* @v boolean value
* activate provenance on all kernel objects. WARNING the computer may slow down
* dramatically and the amount of data generated may be excessively large. Will
* fail if current process is not root.
*/
int provenance_set_all(bool v);

/*
* @v boolean value
* Hide the current process from provenance capture. Should be mostly used by the
* provenance capture service itself. Will fail if the current process is not
* root.
*/
int provenance_set_opaque(bool v);

/*
* @node node data structure to be recorded
* API to dsiclose a provenance node. Some values should be left blank and Will
* be updated by the kernel.
*/
int provenance_disclose_node(struct disc_node_struct* node);

/*
* @edge edge data structure to be recorded
* API to dsiclose a provenance edge. Some values should be left blank and Will
* be updated by the kernel.
*/
int provenance_disclose_edge(struct edge_struct* edge);

/*
* @self point to a node data structure
* self if filled with the provenance information corresponding to the current
* process.
*/
int provenance_self(struct task_prov_struct* self);

#endif /* __PROVENANCELIB_H */
