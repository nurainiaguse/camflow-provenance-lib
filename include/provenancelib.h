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
  bool (*filter)(union prov_elt* msg);
  bool (*long_filter)(union long_prov_elt* msg);
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
  void (*log_packet_content)(struct pckcnt_struct*);
  /* callback for library errors */
  void (*log_error)(char*);
};

void prov_record(union prov_elt* msg);
void long_prov_record(union long_prov_elt* msg);

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

/*
* return if current process is opaque or not.
*/
bool provenance_get_opaque(void);

/*
* @v boolean value
* Request the current process to be part of the provenance record (even if 'all'
* is not set).
*/
int provenance_set_tracked(bool v);

/*
* return if current process is tracked or not.
*/
bool provenance_get_tracked(void);

/*
* @v boolean value
* Request the current process to propagate tracking.
*/
int provenance_set_propagate(bool v);

/*
* return if current process propagate tracking or not.
*/
bool provenance_get_propagate(void);

/*
* apply label to current process.
*/
int provenance_label(const char *label);

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
int provenance_read_file(const char name[PATH_MAX], union prov_elt* inode_info);

/*
* @name file name
* @track boolean either to track or not the file
* set tracking option corresponding to the file associated with name
*/
int provenance_track_file(const char name[PATH_MAX], bool track);

/*
* @fd file descriptor
* @track boolean either to track or not the file
* set tracking option corresponding to the file associated with fd
*/
int fprovenance_track_file(int fd, bool track);

/*
* @name file name
* @opaque boolean either to make opaque or not the file
* make the file opaque to provenance tracking.
*/
int provenance_opaque_file(const char name[PATH_MAX], bool opaque);

/*
* @fd file descriptor
* @opaque boolean either to make opaque or not the file
* make the file opaque to provenance tracking.
*/
int fprovenance_opaque_file(int fd, bool opaque);

/*
* @name file name
* @propagate boolean either to propagate tracking or not
* set propagate option corresponding to the file associated with name
*/
int provenance_propagate_file(const char name[PATH_MAX], bool propagate);

/*
* @fd file descriptor
* @propagate boolean either to propagate tracking or not
* set propagate option corresponding to the file associated with fd
*/
int fprovenance_propagate_file(int fd, bool propagate);

/*
* @name file name
* @label label to be applied to the file
* add label to the file corresponding to name
*/
int provenance_label_file(const char name[PATH_MAX], const char *label);

/*
* @fd file descriptor
* @label label to be applied to the file
* add label to the file corresponding to fd
*/
int fprovenance_label_file(int fd, const char *label);

/*
* @pid process pid
* @inode_info point to an inode_info structure
* retrieve provenance information of the process associated with pid.
*/
int provenance_read_process(uint32_t pid, union prov_elt* process_info);

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

int provenance_label_process(uint32_t pid, const char *label);

int provenance_ingress_ipv4_track(const char* param);
int provenance_ingress_ipv4_propagate(const char* param);
int provenance_ingress_ipv4_record(const char* param);
int provenance_ingress_ipv4_delete(const char* param);
int provenance_ingress_ipv4( struct prov_ipv4_filter* filters, size_t length );

int provenance_egress_ipv4_track(const char* param);
int provenance_egress_ipv4_propagate(const char* param);
int provenance_egress_ipv4_record(const char* param);
int provenance_egress_ipv4_delete(const char* param);
int provenance_egress_ipv4( struct prov_ipv4_filter* filters, size_t length );

int provenance_secid_to_secctx( uint32_t secid, char* secctx, uint32_t len);

int provenance_secctx_track(const char* secctx);
int provenance_secctx_propagate(const char* secctx);
int provenance_secctx_delete(const char* secctx);
int provenance_secctx( struct secinfo* filters, size_t length );

int provenance_cgroup_track(const uint32_t cid);
int provenance_cgroup_propagate(const uint32_t cid);
int provenance_cgroup_delete(const uint32_t cid);
int provenance_cgroup( struct cgroupinfo* filters, size_t length );

#endif /* __PROVENANCELIB_H */
