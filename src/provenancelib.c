/*
*
* provenancelib.c
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

#include "thpool.h"
#include "provenancelib.h"

#define NUMBER_CPUS           256 /* support 256 core max */
#define PROV_BASE_NAME        "/sys/kernel/debug/provenance"
#define LONG_PROV_BASE_NAME   "/sys/kernel/debug/long_provenance"

/* internal variables */
static struct provenance_ops prov_ops;
static uint8_t ncpus;
/* per cpu variables */
static int relay_file[NUMBER_CPUS];
static int long_relay_file[NUMBER_CPUS];
/* worker pool */
static threadpool worker_thpool=NULL;

/* internal functions */
static int open_files(void);
static int close_files(void);
static int create_worker_pool(void);
static int destroy_worker_pool(void);

static void callback_job(void* data);
static void long_callback_job(void* data);
static void reader_job(void *data);
static void long_reader_job(void *data);


int provenance_register(struct provenance_ops* ops)
{
  int err;
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
    sprintf(tmp, "%s%d", PROV_BASE_NAME, i);
    relay_file[i] = open(tmp, O_RDONLY | O_NONBLOCK);
    if(relay_file[i]<0){
      return -1;
    }
    sprintf(tmp, "%s%d", LONG_PROV_BASE_NAME, i);
    long_relay_file[i] = open(tmp, O_RDONLY | O_NONBLOCK);
    if(long_relay_file[i]<0){
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

/* handle application callbacks */
static void callback_job(void* data)
{
  prov_msg_t* msg = (prov_msg_t*)data;

  /* initialise per worker thread */
  if(!initialised && prov_ops.init!=NULL){
    prov_ops.init();
    initialised=1;
  }

  switch(msg->msg_info.msg_info.type){
    case MSG_EDGE:
      if(prov_ops.log_edge!=NULL)
        prov_ops.log_edge(&(msg->edge_info));
      break;
    case MSG_TASK:
      if(prov_ops.log_task!=NULL)
        prov_ops.log_task(&(msg->task_info));
      break;
    case MSG_INODE:
      if(prov_ops.log_inode!=NULL)
        prov_ops.log_inode(&(msg->inode_info));
      break;
    case MSG_DISC_NODE:
      if(prov_ops.log_disc!=NULL)
        prov_ops.log_disc(&(msg->disc_node_info));
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
    default:
      printf("Error: unknown message type %u\n", msg->msg_info.msg_info.type);
      break;
  }
  free(data); /* free the memory allocated in the reader */
}

/* handle application callbacks */
static void long_callback_job(void* data)
{
  long_prov_msg_t* msg = (long_prov_msg_t*)data;

  /* initialise per worker thread */
  if(!initialised && prov_ops.init!=NULL){
    prov_ops.init();
    initialised=1;
  }

  switch(msg->msg_info.msg_info.type){
    case MSG_STR:
      if(prov_ops.log_str!=NULL)
        prov_ops.log_str(&(msg->str_info));
      break;
    case MSG_LINK:
      if(prov_ops.log_link!=NULL)
        prov_ops.log_link(&(msg->link_info));
      break;
    case MSG_UNLINK:
      if(prov_ops.log_unlink!=NULL)
        prov_ops.log_unlink(&(msg->unlink_info));
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
    default:
      printf("Error: unknown message type %u\n", msg->msg_info.msg_info.type);
      break;
  }
  free(data); /* free the memory allocated in the reader */
}

/* read from relayfs file */
static void reader_job(void *data)
{
  uint8_t* buf;
  size_t size;
  int rc;
  uint8_t cpu = (uint8_t)(*(uint8_t*)data);
  struct pollfd pollfd;

  do{
    /* file to look on */
    pollfd.fd = relay_file[cpu];
    /* something to read */
		pollfd.events = POLLIN;
    /* one file, timeout 100ms */
    rc = poll(&pollfd, 1, 100);
    if(rc<0){
      if(errno!=EINTR){
        break; /* something bad happened */
      }
    }
    buf = (uint8_t*)malloc(sizeof(prov_msg_t)); /* freed by worker thread */

    size = 0;
    do{
      rc = read(relay_file[cpu], buf+size, sizeof(prov_msg_t)-size);
      if(rc==0){ /* we did not read anything */
        continue;
      }
      if(rc<0){
        if(errno==EAGAIN){ // retry
          continue;
        }
        thpool_add_work(worker_thpool, (void*)reader_job, (void*)data);
        return; // something bad happened
      }
      size+=rc;
    }while(size<sizeof(prov_msg_t));
    /* add job to queue */
    thpool_add_work(worker_thpool, (void*)callback_job, buf);
  }while(1);
}

/* read from relayfs file */
static void long_reader_job(void *data)
{
  uint8_t* buf;
  size_t size;
  int rc;
  uint8_t cpu = (uint8_t)(*(uint8_t*)data);
  struct pollfd pollfd;

  do{
    /* file to look on */
    pollfd.fd = long_relay_file[cpu];
    /* something to read */
		pollfd.events = POLLIN;
    /* one file, timeout 100ms */
    rc = poll(&pollfd, 1, 100);
    if(rc<0){
      if(errno!=EINTR){
        break; /* something bad happened */
      }
    }
    buf = (uint8_t*)malloc(sizeof(long_prov_msg_t)); /* freed by worker thread */

    size = 0;
    do{
      rc = read(long_relay_file[cpu], buf+size, sizeof(long_prov_msg_t)-size);
      if(rc==0){ /* we did not read anything */
        continue;
      }
      if(rc<0){
        printf("Error %d\n", rc);
        if(errno==EAGAIN){ // retry
          continue;
        }
        thpool_add_work(worker_thpool, (void*)long_reader_job, (void*)data);
        return; // something bad happened
      }
      size+=rc;
    }while(size<sizeof(long_prov_msg_t));
    /* add job to queue */
    thpool_add_work(worker_thpool, (void*)long_callback_job, buf);
  }while(1);
}

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

int provenance_disclose_edge(struct edge_struct* edge){
  int rc;
  int fd = open(PROV_EDGE_FILE, O_WRONLY);

  if(fd<0)
  {
    return fd;
  }
  rc = write(fd, edge, sizeof(struct edge_struct));
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

#define MSG_STR           0
#define MSG_EDGE          1
#define MSG_TASK          2
#define MSG_INODE         3
#define MSG_LINK          4
#define MSG_UNLINK        5
#define MSG_DISC_NODE     6
#define MSG_MSG           7
#define MSG_SHM           8
#define MSG_SOCK          9
#define MSG_ADDR          10
#define MSG_SB            11
#define MSG_FILE_NAME     12
#define MSG_IFC           13

static char* msg_type[] = {"string", "flow", "task", "inode", "link", "unlink", "disclosed", "message", "shared memory", "socket", "address", "super block", "file name", "ifc"};

char* msg_info_to_json(char* buffer, struct basic_msg_info* m){
  sprintf(buffer, "{\"type\":\"%s\", \"id\":%llu, \"machine_id\":%u, \"boot_id\":%u}", msg_type[m->type], m->id , m->machine_id, m->boot_id);
  return buffer;
}

char* node_basic_to_json(char* buffer, struct basic_node_info* n){
  sprintf(buffer, "{\"id\":%llu, \"boot_id\":%u, \"machine_id\":%u, \"version\":%u}", n->id, n->boot_id, n->machine_id, n->version);
  return buffer;
}

static char* bool_str[] = {"false", "true"};

char* edge_to_json(char* buffer, struct edge_struct* e){
  char msg_info[1024];
  char sender[1024];
  char receiver[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"type\":\"%s\", \"allowed\":%s, \"sender\":%s, \"receiver\":%s}",
    msg_info_to_json(msg_info, &e->msg_info),
    edge_str[e->type],
    bool_str[e->allowed],
    node_basic_to_json(sender, &e->snd),
    node_basic_to_json(receiver, &e->rcv));
  return buffer;
}

char* disc_to_json(char* buffer, struct disc_node_struct* n){
  char msg_info[1024];
  char node_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"node_info\":%s}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(node_info, &n->node_info));
  return buffer;
}

char* task_to_json(char* buffer, struct task_prov_struct* n){
  char msg_info[1024];
  char node_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"node_info\":%s, \"user_id\":%u, \"group_id\":%u}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(node_info, &n->node_info),
    n->uid,
    n->gid);
  return buffer;
}

#define UUID_STR_SIZE 37
char* uuid_to_str(uint8_t* uuid, char* str, size_t size){
  if(size<37){
    sprintf(str, "UUID-ERROR");
    return str;
  }
  sprintf(str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    uuid[0], uuid[1], uuid[2], uuid[3]
    , uuid[4], uuid[5]
    , uuid[6], uuid[7]
    , uuid[8], uuid[9]
    , uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    return str;
}

static char STR_UNKNOWN[]= "unknown";
static char STR_BLOCK_SPECIAL[]= "block special";
static char STR_CHAR_SPECIAL[]= "char special";
static char STR_DIRECTORY[]= "directory";
static char STR_FIFO[]= "fifo";
static char STR_LINK[]= "link";
static char STR_FILE[]= "file";
static char STR_SOCKET[]= "socket";

static inline char* get_inode_type(mode_t mode){
  char* type=STR_UNKNOWN;
  if(S_ISBLK(mode))
    type=STR_BLOCK_SPECIAL;
  else if(S_ISCHR(mode))
    type=STR_CHAR_SPECIAL;
  else if(S_ISDIR(mode))
    type=STR_DIRECTORY;
  else if(S_ISFIFO(mode))
    type=STR_FIFO;
  else if(S_ISLNK(mode))
    type=STR_LINK;
  else if(S_ISREG(mode))
    type=STR_FILE;
  else if(S_ISSOCK(mode))
    type=STR_SOCKET;
  return type;
}

char* inode_to_json(char* buffer, struct inode_prov_struct* n){
  char msg_info[1024];
  char node_info[1024];
  char uuid[UUID_STR_SIZE];
  sprintf(buffer, "{\"msg_info\":%s, \"node_info\":%s, \"user_id\":%u, \"group_id\":%u, \"type\":\"%s\", \"mode\":\"0X%04hhX\", \"uuid\":\"%s\"}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(node_info, &n->node_info),
    n->uid,
    n->gid,
    get_inode_type(n->mode),
    n->mode,
    uuid_to_str(n->sb_uuid, uuid, UUID_STR_SIZE));
  return buffer;
}

char* sb_to_json(char* buffer, struct sb_struct* n){
  char msg_info[1024];
  char node_info[1024];
  char uuid[UUID_STR_SIZE];
  sprintf(buffer, "{\"msg_info\":%s, \"node_info\":%s, \"uuid\":\"%s\"}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(node_info, &n->node_info),
    uuid_to_str(n->uuid, uuid, UUID_STR_SIZE));
  return buffer;
}

char* msg_to_json(char* buffer, struct msg_msg_struct* n){
  char msg_info[1024];
  char node_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"node_info\":%s, \"type\":%ld}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(node_info, &n->node_info),
    n->type);
  return buffer;
}

char* shm_to_json(char* buffer, struct shm_struct* n){
  char msg_info[1024];
  char node_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"node_info\":%s, \"mode\":\"0X%04hhX\"}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(node_info, &n->node_info),
    n->mode);
  return buffer;
}

char* sock_to_json(char* buffer, struct sock_struct* n){
  char msg_info[1024];
  char node_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"node_info\":%s, \"type\":%u, \"family\":%u, \"protocol\":%u}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(node_info, &n->node_info),
    n->type,
    n->family,
    n->protocol);
  return buffer;
}

char* str_msg_to_json(char* buffer, struct str_struct* n){
  char msg_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"msg\":\"%s\"}",
    msg_info_to_json(msg_info, &n->msg_info),
    n->str);
  return buffer;
}

char* sockaddr_to_json(char* buffer, struct sockaddr* addr, size_t length){
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];

  if(addr->sa_family == AF_INET){
    getnameinfo(addr, length, host, NI_MAXHOST, serv, NI_MAXSERV, 0);
    sprintf(buffer, "{\"type\":\"AF_INET\", \"host\":\"%s\", \"serv\":\"%s\"}", host, serv);
  }else if(addr->sa_family == AF_INET6){
    getnameinfo(addr, length, host, NI_MAXHOST, serv, NI_MAXSERV, 0);
    sprintf(buffer, "{\"type\":\"AF_INET6\", \"host\":\"%s\", \"serv\":\"%s\"}", host, serv);
  }else if(addr->sa_family == AF_UNIX){
    sprintf(buffer, "{\"type\":\"AF_UNIX\", \"path\":\"%s\"}", ((struct sockaddr_un*)addr)->sun_path);
  }else{
    sprintf(buffer, "{\"type\":\"OTHER\"}");
  }

  return buffer;
}

char* addr_to_json(char* buffer, struct address_struct* n){
  char msg_info[1024];
  char node_info[1024];
  char addr_info[PATH_MAX+1024];
  sprintf(buffer, "{\"msg_info\":%s, \"node_info\":%s, \"address\":%s}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(node_info, &n->sock_info),
    sockaddr_to_json(addr_info, &n->addr, n->length));
  return buffer;
}

char* link_to_json(char* buffer, struct link_struct* n){
  char msg_info[1024];
  char dir_info[1024];
  char task_info[1024];
  char inode_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"dir\":%s, \"task\":%s, \"inode\":%s, \"name\":\"%s\"}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(dir_info, &n->dir),
    node_basic_to_json(task_info, &n->task),
    node_basic_to_json(inode_info, &n->inode),
    n->name);
  return buffer;
}

char* unlink_to_json(char* buffer, struct unlink_struct* n){
  char msg_info[1024];
  char dir_info[1024];
  char task_info[1024];
  char inode_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"dir\":%s, \"task\":%s, \"inode\":%s, \"name\":\"%s\"}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(dir_info, &n->dir),
    node_basic_to_json(task_info, &n->task),
    node_basic_to_json(inode_info, &n->inode),
    n->name);
  return buffer;
}

char* pathname_to_json(char* buffer, struct file_name_struct* n){
  char msg_info[1024];
  char dir_info[1024];
  char task_info[1024];
  char inode_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"inode\":%s, \"name\":\"%s\"}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(inode_info, &n->inode),
    n->name);
  return buffer;
}

char* ifc_to_json(char* buffer, struct ifc_context_struct* n){
  char msg_info[1024];
  char node_info[1024];
  sprintf(buffer, "{\"msg_info\":%s, \"node_info\":%s, \"ifc\":\"TODO\"}",
    msg_info_to_json(msg_info, &n->msg_info),
    node_basic_to_json(node_info, &n->node_info));
  return buffer;
}
