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
#include <sys/stat.h>
#include <sys/poll.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

#include "thpool.h"
#include "provenancelib.h"

#define RUN_PID_FILE "/run/provenance-service.pid"

/*
* TODO look at code to avoid duplication across normal and "long" relay
*/

#define NUMBER_CPUS           256 /* support 256 core max */

/* internal variables */
static struct provenance_ops prov_ops;
static uint8_t ncpus;
/* per cpu variables */
static int relay_file[NUMBER_CPUS];
static int long_relay_file[NUMBER_CPUS];
/* worker pool */
static threadpool worker_thpool=NULL;
static uint32_t machine_id=0;

/* internal functions */
static int open_files(void);
static int close_files(void);
static int create_worker_pool(void);
static void destroy_worker_pool(void);

static void callback_job(void* data, const size_t prov_size);
static void long_callback_job(void* data, const size_t prov_size);
static void reader_job(void *data);
static void long_reader_job(void *data);

static inline void record_error(const char* fmt, ...){
  char tmp[2048];
	va_list args;

	va_start(args, fmt);
	vsnprintf(tmp, 2048, fmt, args);
	va_end(args);
  if(prov_ops.log_error!=NULL){
    prov_ops.log_error(tmp);
  }
}

int provenance_record_pid( void ){
  int err;
  pid_t pid = getpid();
  FILE *f = fopen(RUN_PID_FILE, "w");
  if(f==NULL){
    return -1;
  }
  err = fprintf(f, "%d", pid);
  fclose(f);
  return err;
}

int provenance_register(struct provenance_ops* ops)
{
  int err;

  provenance_get_machine_id(&machine_id);

  /* the provenance usher will not appear in trace */
  err = provenance_set_opaque(true);
  if(err)
  {
    return err;
  }
  /* copy ops function pointers */
  memcpy(&prov_ops, ops, sizeof(struct provenance_ops));

  /* count how many CPU */
  ncpus = sysconf(_SC_NPROCESSORS_ONLN);
  if(ncpus>NUMBER_CPUS){
    return -1;
  }

  /* open relay files */
  if(open_files()){
    return -1;
  }

  /* create callback threads */
  if(create_worker_pool()){
    close_files();
    return -1;
  }

  if(provenance_record_pid() < 0){
    return -1;
  }
  return 0;
}

void provenance_stop()
{
  close_files();
  destroy_worker_pool();
}

static int open_files(void)
{
  int i;
  char tmp[4096]; // to store file name

  tmp[0]='\0';
  for(i=0; i<ncpus; i++){
    snprintf(tmp, 4096-strlen(tmp), "%s%d", PROV_RELAY_NAME, i);
    relay_file[i] = open(tmp, O_RDONLY | O_NONBLOCK);
    if(relay_file[i]<0){
      record_error("Could not open files (%d)\n", relay_file[i]);
      return -1;
    }
    snprintf(tmp, 4096-strlen(tmp), "%s%d", PROV_LONG_RELAY_NAME, i);
    long_relay_file[i] = open(tmp, O_RDONLY | O_NONBLOCK);
    if(long_relay_file[i]<0){
      record_error("Could not open files (%d)\n", long_relay_file[i]);
      return -1;
    }
  }
  return 0;
}

static int close_files(void)
{
  int i;
  for(i=0; i<ncpus;i++){
    close(relay_file[i]);
    close(long_relay_file[i]);
  }
  return 0;
}

static int create_worker_pool(void)
{
  int i;
  uint8_t* cpunb;
  worker_thpool = thpool_init(ncpus*2);
  /* set reader jobs */
  for(i=0; i<ncpus; i++){
    cpunb = (uint8_t*)malloc(sizeof(uint8_t)); // will be freed in worker
    (*cpunb)=i;
    thpool_add_work(worker_thpool, (void*)reader_job, (void*)cpunb);
    thpool_add_work(worker_thpool, (void*)long_reader_job, (void*)cpunb);
  }
  return 0;
}

static void destroy_worker_pool(void)
{
  thpool_wait(worker_thpool); // wait for all jobs in queue to be finished
  thpool_destroy(worker_thpool); // destory all worker threads
}

/* per worker thread initialised variable */
static __thread int initialised=0;

void relation_record(union prov_elt *msg){
  uint64_t w3c_type = W3C_TYPE(prov_type(msg));
  switch(w3c_type){
    case RL_DERIVED:
      if(prov_ops.log_derived!=NULL)
        prov_ops.log_derived(&(msg->relation_info));
      break;
    case RL_GENERATED:
      if(prov_ops.log_generated!=NULL)
        prov_ops.log_generated(&(msg->relation_info));
      break;
    case RL_USED:
      if(prov_ops.log_used!=NULL)
        prov_ops.log_used(&(msg->relation_info));
      break;
    case RL_INFORMED:
      if(prov_ops.log_informed!=NULL)
        prov_ops.log_informed(&(msg->relation_info));
      break;
    default:
      if(prov_ops.log_unknown_relation!=NULL)
        prov_ops.log_unknown_relation(&(msg->relation_info));
      break;
  }
}

void node_record(union prov_elt *msg){
  switch(prov_type(msg)){
    case ACT_TASK:
      if(prov_ops.log_task!=NULL)
        prov_ops.log_task(&(msg->task_info));
      break;
    case ENT_INODE_UNKNOWN:
    case ENT_INODE_LINK:
    case ENT_INODE_FILE:
    case ENT_INODE_DIRECTORY:
    case ENT_INODE_CHAR:
    case ENT_INODE_BLOCK:
    case ENT_INODE_FIFO:
    case ENT_INODE_SOCKET:
    case ENT_INODE_MMAP:
      if(prov_ops.log_inode!=NULL)
        prov_ops.log_inode(&(msg->inode_info));
      break;
    case ENT_MSG:
      if(prov_ops.log_msg!=NULL)
        prov_ops.log_msg(&(msg->msg_msg_info));
      break;
    case ENT_SHM:
      if(prov_ops.log_shm!=NULL)
        prov_ops.log_shm(&(msg->shm_info));
      break;
    case ENT_PACKET:
      if(prov_ops.log_packet!=NULL)
        prov_ops.log_packet(&(msg->pck_info));
      break;
    case ENT_IATTR:
      if(prov_ops.log_iattr!=NULL)
        prov_ops.log_iattr(&(msg->iattr_info));
      break;
    default:
      record_error("Error: unknown type %llu\n", prov_type(msg));
      break;
  }
}

void prov_record(union prov_elt* msg){

  if(prov_is_relation(msg))
    relation_record(msg);
  else
    node_record(msg);
}

/* handle application callbacks */
static void callback_job(void* data, const size_t prov_size)
{
  union prov_elt* msg;
  if(prov_size!=sizeof(union prov_elt)){
    record_error("Wrong size %d expected: %d.", prov_size, sizeof(union prov_elt));
    return;
  }
  msg = (union prov_elt*)data;
  if(prov_type(msg)!=ENT_PACKET){
    node_identifier(msg).machine_id = machine_id;
  }

  /* initialise per worker thread */
  if(!initialised && prov_ops.init!=NULL){
    prov_ops.init();
    initialised=1;
  }

  // dealing with filter
  if(prov_ops.filter!=NULL){
    if(prov_ops.filter((prov_entry_t*)msg)) // message has been fitlered
      goto out;
  }

  prov_record(msg);
out:
  free(data); /* free the memory allocated in the reader */
}

void long_prov_record(union long_prov_elt* msg){
  switch(prov_type(msg)){
    case ENT_STR:
      if(prov_ops.log_str!=NULL)
        prov_ops.log_str(&(msg->str_info));
      break;
    case ENT_FILE_NAME:
      if(prov_ops.log_file_name!=NULL)
        prov_ops.log_file_name(&(msg->file_name_info));
      break;
    case ENT_ADDR:
      if(prov_ops.log_address!=NULL)
        prov_ops.log_address(&(msg->address_info));
      break;
    case ENT_XATTR:
      if(prov_ops.log_xattr!=NULL)
        prov_ops.log_xattr(&(msg->xattr_info));
      break;
    case ENT_DISC:
    case ACT_DISC:
    case AGT_DISC:
      if(prov_ops.log_disc!=NULL)
        prov_ops.log_disc(&(msg->disc_node_info));
      break;
    case ENT_PCKCNT:
      if(prov_ops.log_packet_content!=NULL)
        prov_ops.log_packet_content(&(msg->pckcnt_info));
      break;
    default:
      record_error("Error: unknown long type %llu\n", prov_type(msg));
      break;
  }
}

/* handle application callbacks */
static void long_callback_job(void* data, const size_t prov_size)
{
  union long_prov_elt* msg;
  if(prov_size!=sizeof(union long_prov_elt)){
    record_error("Wrong size %d expected: %d.", prov_size, sizeof(union long_prov_elt));
    return;
  }
  msg = (union long_prov_elt*)data;
  node_identifier(msg).machine_id = machine_id;

  /* initialise per worker thread */
  if(!initialised && prov_ops.init!=NULL){
    prov_ops.init();
    initialised=1;
  }

  // dealing with filter
  if(prov_ops.filter!=NULL){
    if(prov_ops.filter((prov_entry_t*)msg)) // message has been fitlered
      goto out;
  }

  long_prov_record(msg);
out:
  free(data); /* free the memory allocated in the reader */
}

#define buffer_size(prov_size) (prov_size*1000)
static void ___read_relay( const int relay_file, const size_t prov_size, void (*callback)(void*, const size_t)){
	uint8_t *buf;
	uint8_t* entry;
  size_t size=0;
  size_t i=0;
  int rc;
	buf = (uint8_t*)malloc(buffer_size(prov_size));
	do{
		rc = read(relay_file, buf+size, buffer_size(prov_size)-size);
		if(rc<0){
			record_error("Failed while reading (%d).", errno);
			if(errno==EAGAIN) // retry
				continue;
			free(buf);
			return;
		}
		size += rc;
	}while(size%prov_size!=0);

	while(size>0){
		entry = (uint8_t*)malloc(prov_size);
		memcpy(entry, buf+i, prov_size);
		size-=prov_size;
		i+=prov_size;
		callback(entry, prov_size);
	}
	free(buf);
}

#define POL_FLAG (POLLIN|POLLRDNORM|POLLERR)
#define RELAY_POLL_TIMEOUT 1000L

/* read from relayfs file */
static void reader_job(void *data)
{
  int rc;
  uint8_t cpu = (uint8_t)(*(uint8_t*)data);
  struct pollfd pollfd;

  do{
    /* file to look on */
    pollfd.fd = relay_file[cpu];
    /* something to read */
		pollfd.events = POL_FLAG;
    /* one file, timeout */
    rc = poll(&pollfd, 1, RELAY_POLL_TIMEOUT);
    if(rc<0){
      record_error("Failed while polling (%d).", rc);
      continue; /* something bad happened */
    }
    ___read_relay(relay_file[cpu], sizeof(union prov_elt), callback_job);
  }while(1);
}

#define US	1000L
#define MS 	1000000L
/* read from relayfs file */
static void long_reader_job(void *data)
{
  int rc;
  uint8_t cpu = (uint8_t)(*(uint8_t*)data);
  struct pollfd pollfd;
	struct timespec s;

	s.tv_sec=0;
	s.tv_nsec=5*MS;
  do{
		nanosleep(&s, NULL);
    /* file to look on */
    pollfd.fd = long_relay_file[cpu];
    /* something to read */
		pollfd.events = POL_FLAG;
    /* one file, timeout */
    rc = poll(&pollfd, 1, RELAY_POLL_TIMEOUT);
    if(rc<0){
      record_error("Failed while polling (%d).", rc);
      continue; /* something bad happened */
    }
    ___read_relay(long_relay_file[cpu], sizeof(union long_prov_elt), long_callback_job);
  }while(1);
}
