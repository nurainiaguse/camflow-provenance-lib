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
#ifndef __PROVENANCELIB_H
#define __PROVENANCELIB_H


#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/provenance.h>

struct provenance_ops{
  void (*init)(void);
  bool (*filter)(prov_msg_t* msg);
  bool (*long_filter)(long_prov_msg_t* msg);
  /* relation callback */
  void (*log_unknown_relation)(struct relation_struct*);
  void (*log_derived)(struct relation_struct*);
  void (*log_generated)(struct relation_struct*);
  void (*log_used)(struct relation_struct*);
  void (*log_informed)(struct relation_struct*);
  /* nodes callback */
  void (*log_task)(struct task_prov_struct*);
  void (*log_inode)(struct inode_prov_struct*);
  void (*log_str)(struct str_struct*);
  void (*log_disc)(struct disc_node_struct*);
  void (*log_msg)(struct msg_msg_struct*);
  void (*log_shm)(struct shm_struct*);
  void (*log_packet)(struct pck_struct*);
  void (*log_address)(struct address_struct*);
  void (*log_file_name)(struct file_name_struct*);
  void (*log_iattr)(struct iattr_prov_struct*);
  void (*log_xattr)(struct xattr_prov_struct*);
  /* callback for library erros */
  void (*log_error)(char*);
};

void prov_record(prov_msg_t* msg);
void long_prov_record(long_prov_msg_t* msg);

/*
* Function return boolean value corresponding to the presence or not of the
* provenance module in the kernel.
*/
bool provenance_is_present(void);

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
* return either or not the provenance capture is active.
*/
bool provenance_get_enable( void );

/*
* @v boolean value
* activate provenance on all kernel objects. WARNING the computer may slow down
* dramatically and the amount of data generated may be excessively large. Will
* fail if current process is not root.
*/
int provenance_set_all(bool v);

/*
* return either or not provenance on all kernel object is active.
*/
bool provenance_get_all( void );

/*
* @v boolean value
* Hide the current process from provenance capture. Should be mostly used by the
* provenance capture service itself. Will fail if the current process is not
* root.
*/
int provenance_set_opaque(bool v);
bool provenance_get_opaque(void);

/*
* @v boolean value
* Request the current process to be part of the provenance record (even if 'all'
* is not set).
*/
int provenance_set_tracked(bool v);
bool provenance_get_tracked(void);

int provenance_set_propagate(bool v);
bool provenance_get_propagate(void);

/*
* @v uint32_t value
* Assign an ID to the current machine. Will fail if the current process is not
* root.
*/
int provenance_set_machine_id(uint32_t v);

/*
* @v pointer to uint32_t value
* Read the machine ID corresponding to the current machine.
*/
int provenance_get_machine_id(uint32_t* v);

/*
* @node node data structure to be recorded
* API to dsiclose a provenance node. Some values should be left blank and Will
* be updated by the kernel.
*/
int provenance_disclose_node(struct disc_node_struct* node);

/*
* @relation relation data structure to be recorded
* API to dsiclose a provenance relation. Some values should be left blank and Will
* be updated by the kernel.
*/
int provenance_disclose_relation(struct relation_struct* relation);

/*
* @self point to a node data structure
* self if filled with the provenance information corresponding to the current
* process.
*/
int provenance_self(struct task_prov_struct* self);

/*
* flush the current relay subuffers.
*/
int provenance_flush(void);

/*
* @name file name
* @inode_info point to an inode_info structure
* retrieve provenance information of the file associated with name.
*/
int provenance_read_file(const char name[PATH_MAX], prov_msg_t* inode_info);

/*
* @name file name
* @track boolean either to track or not the file
* set tracking option corresponding to the file associated with name
*/
int provenance_track_file(const char name[PATH_MAX], bool track);

/*
* @name file name
* @opaque boolean either to make opaque or not the file
* make the file opaque to provenance tracking.
*/
int provenance_opaque_file(const char name[PATH_MAX], bool opaque);

int provenance_propagate_file(const char name[PATH_MAX], bool propagate);

int provenance_taint_file(const char name[PATH_MAX], uint64_t taint);

/*
* @pid process pid
* @inode_info point to an inode_info structure
* retrieve provenance information of the process associated with pid.
*/
int provenance_read_process(uint32_t pid, prov_msg_t* process_info);

/*
* @pid process pid
* @track boolean either to track or not the file
* set tracking option corresponding to the proccess associated with pid
*/
int provenance_track_process(uint32_t pid, bool track);

/*
* @pid process pid
* @opaque boolean either to make opaque or not the file
* make the process opaque to provenance tracking.
*/
int provenance_opaque_process(uint32_t pid, bool opaque);

int provenance_propagate_process(uint32_t pid, bool propagate);

int provenance_taint_process(uint32_t pid, uint64_t taint);

int provenance_ingress_ipv4_track(const char* param);
int provenance_ingress_ipv4_propagate(const char* param);
int provenance_ingress_ipv4_delete(const char* param);
int provenance_ingress_ipv4( struct prov_ipv4_filter* filters, size_t length );

int provenance_egress_ipv4_track(const char* param);
int provenance_egress_ipv4_propagate(const char* param);
int provenance_egress_ipv4_delete(const char* param);
int provenance_egress_ipv4( struct prov_ipv4_filter* filters, size_t length );

int provenance_secid_to_secctx( uint32_t secid, char* secctx, uint32_t len);

#endif /* __PROVENANCELIB_H */
