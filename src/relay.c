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

#include "thpool.h"
#include "provenancelib.h"

/*
* TODO look at code to avoid duplication across normal and "long" relay
*/

#define NUMBER_CPUS           256 /* support 256 core max */

#define RELAY_POLL_TIMEOUT 50

/* internal variables */
static struct provenance_ops prov_ops;
static uint8_t ncpus;
/* per cpu variables */
static int relay_file[NUMBER_CPUS];
static int long_relay_file[NUMBER_CPUS];
/* worker pool */
static threadpool worker_thpool=NULL;
/* machine_id */
static uint32_t machine_id=0;

/* internal functions */
static int open_files(void);
static int close_files(void);
static int create_worker_pool(void);
static int destroy_worker_pool(void);

static void callback_job(void* data);
static void long_callback_job(void* data);
static void reader_job(void *data);
static void long_reader_job(void *data);

static inline void record_error(const char* fmt, ...){
  char tmp[2048];
	va_list args;

	va_start(args, fmt);
	vsprintf(tmp, fmt, args);
	va_end(args);
  prov_ops.log_error(tmp);
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

  for(i=0; i<ncpus; i++){
    sprintf(tmp, "%s%d", PROV_RELAY_NAME, i);
    relay_file[i] = open(tmp, O_RDONLY | O_NONBLOCK);
    if(relay_file[i]<0){
      record_error("Could not open files (%d)\n", relay_file[i]);
      return -1;
    }
    sprintf(tmp, "%s%d", PROV_LONG_RELAY_NAME, i);
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
  worker_thpool = thpool_init(ncpus*4);
  /* set reader jobs */
  for(i=0; i<ncpus; i++){
    cpunb = (uint8_t*)malloc(sizeof(uint8_t)); // will be freed in worker
    (*cpunb)=i;
    thpool_add_work(worker_thpool, (void*)reader_job, (void*)cpunb);
    thpool_add_work(worker_thpool, (void*)long_reader_job, (void*)cpunb);
  }
}

static int destroy_worker_pool(void)
{
  thpool_wait(worker_thpool); // wait for all jobs in queue to be finished
  thpool_destroy(worker_thpool); // destory all worker threads
}

/* per worker thread initialised variable */
static __thread int initialised=0;

void prov_record(prov_msg_t* msg){
  switch(prov_type(msg)){
    case MSG_RELATION:
      if(prov_ops.log_relation!=NULL)
        prov_ops.log_relation(&(msg->relation_info));
      break;
    case MSG_TASK:
      if(prov_ops.log_task!=NULL)
        prov_ops.log_task(&(msg->task_info));
      break;
    case MSG_INODE_UNKNOWN:
    case MSG_INODE_LINK:
    case MSG_INODE_FILE:
    case MSG_INODE_DIRECTORY:
    case MSG_INODE_CHAR:
    case MSG_INODE_BLOCK:
    case MSG_INODE_FIFO:
    case MSG_INODE_SOCKET:
    case MSG_INODE_MMAP:
      if(prov_ops.log_inode!=NULL)
        prov_ops.log_inode(&(msg->inode_info));
      break;
    case MSG_MSG:
      if(prov_ops.log_msg!=NULL)
        prov_ops.log_msg(&(msg->msg_msg_info));
      break;
    case MSG_SHM:
      if(prov_ops.log_shm!=NULL)
        prov_ops.log_shm(&(msg->shm_info));
      break;
    case MSG_SOCK:
      if(prov_ops.log_sock!=NULL)
        prov_ops.log_sock(&(msg->sock_info));
      break;
    case MSG_PACKET:
      if(prov_ops.log_packet!=NULL)
        prov_ops.log_packet(&(msg->pck_info));
      break;
    default:
      record_error("Error: unknown message type %u\n", prov_type(msg));
      break;
  }
}

/* handle application callbacks */
static void callback_job(void* data)
{
  prov_msg_t* msg = (prov_msg_t*)data;
  if(prov_type(msg)!=MSG_PACKET){
    node_identifier(msg).machine_id = machine_id;
  }

  /* initialise per worker thread */
  if(!initialised && prov_ops.init!=NULL){
    prov_ops.init();
    initialised=1;
  }

  // dealing with filter
  if(prov_ops.filter!=NULL){
    if(prov_ops.filter(msg)){ // message has been fitlered
      goto out;
    }
  }

  prov_record(msg);
out:
  free(data); /* free the memory allocated in the reader */
}

void long_prov_record(long_prov_msg_t* msg){
  switch(prov_type(msg)){
    case MSG_STR:
      if(prov_ops.log_str!=NULL)
        prov_ops.log_str(&(msg->str_info));
      break;
    case MSG_FILE_NAME:
      if(prov_ops.log_file_name!=NULL)
        prov_ops.log_file_name(&(msg->file_name_info));
      break;
    case MSG_ADDR:
      if(prov_ops.log_address!=NULL)
        prov_ops.log_address(&(msg->address_info));
      break;
    case MSG_IFC:
      if(prov_ops.log_ifc!=NULL)
        prov_ops.log_ifc(&(msg->ifc_info));
      break;
    case MSG_DISC_ENTITY:
    case MSG_DISC_ACTIVITY:
    case MSG_DISC_AGENT:
    case MSG_DISC_NODE:
      if(prov_ops.log_disc!=NULL)
        prov_ops.log_disc(&(msg->disc_node_info));
      break;
    default:
      record_error("Error: unknown message type %u\n", prov_type(msg));
      break;
  }
}

/* handle application callbacks */
static void long_callback_job(void* data)
{
  long_prov_msg_t* msg = (long_prov_msg_t*)data;
  node_identifier(msg).machine_id = machine_id;

  /* initialise per worker thread */
  if(!initialised && prov_ops.init!=NULL){
    prov_ops.init();
    initialised=1;
  }

  // dealing with filter
  if(prov_ops.long_filter!=NULL){
    if(prov_ops.long_filter(msg)){ // message has been fitlered
      goto out;
    }
  }

  long_prov_record(msg);
out:
  free(data); /* free the memory allocated in the reader */
}


static void ___read_relay( const int relay_file, const size_t prov_size, const void* callback){
  uint8_t* buf;
  size_t size;
  int rc;

  while(1){
    buf = (uint8_t*)malloc(prov_size); /* freed by worker thread */
    size = 0;
    do{
      rc = read(relay_file, buf+size, prov_size-size);

      if(rc==0 && size==0){
        free(buf);
        return;
      }

      if(rc<0){
        record_error("Failed while reading (%d).", errno);
        if(errno==EAGAIN){ // retry
          continue;
        }
        free(buf);
        return;
      }
      size+=rc;
    }while(size<prov_size);
    /* add job to queue */
    thpool_add_work(worker_thpool, callback, buf);
  }
}

#define POL_FLAG (POLLIN|POLLRDNORM|POLLERR)

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
    ___read_relay(relay_file[cpu], sizeof(prov_msg_t), callback_job);
  }while(1);
}

/* read from relayfs file */
static void long_reader_job(void *data)
{
  int rc;
  uint8_t cpu = (uint8_t)(*(uint8_t*)data);
  struct pollfd pollfd;

  do{
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
    ___read_relay(long_relay_file[cpu], sizeof(long_prov_msg_t), long_callback_job);
  }while(1);
}
