/*
* CamFlow userspace audit example
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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>

#include "simplog.h"
#include "provenancelib.h"

#define	LOG_FILE "/tmp/audit.log"
#define gettid() syscall(SYS_gettid)

static uint32_t hostid=0;

void label_to_str(const uint64_t* in, const size_t in_size, char* out, size_t out_size){
  int i;
	size_t rm = out_size,cx;
	out[0]='\0';
  for(i = 0; i < in_size-1; i++){
		cx = snprintf(out, rm, "%llu, ", in[i]);
		if(cx<0){
			out[0]='\0';
			return;
		}
		out+=cx;
		rm-=cx;
  }
	cx = snprintf(out, rm, "%llu", in[i]);
	if(cx<0){
		out[0]='\0';
		return;
	}
}

unsigned char charset[]={"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};

unsigned char revchar(char ch)
{
   if (ch >= 'A' && ch <= 'Z')
      ch -= 'A';
   else if (ch >= 'a' && ch <='z')
      ch = ch - 'a' + 26;
   else if (ch >= '0' && ch <='9')
      ch = ch - '0' + 52;
   else if (ch == '+')
      ch = 62;
   else if (ch == '/')
      ch = 63;
   return(ch);
}

#define base64_buff_size_for_type(type) ((sizeof(type)/3)*4 + 2)

size_t base64_encode(uint8_t in[], uint8_t out[], size_t len, int newline_flag)
{
   size_t idx,idx2,blks,left_over;
   // Since 3 input bytes = 4 output bytes, figure out how many even sets of 3 input bytes
   // there are and process those. Multiplying by the equivilent of 3/3 (int arithmetic)
   // will reduce a number to the lowest multiple of 3.
   blks = (len / 3) * 3;
   for (idx=0,idx2=0; idx < blks; idx += 3,idx2 += 4) {
      out[idx2] = charset[in[idx] >> 2];
      out[idx2+1] = charset[((in[idx] & 0x03) << 4) + (in[idx+1] >> 4)];
      out[idx2+2] = charset[((in[idx+1] & 0x0f) << 2) + (in[idx+2] >> 6)];
      out[idx2+3] = charset[in[idx+2] & 0x3F];
      // The offical standard requires insertion of a newline every 76 chars
      if (!(idx2 % 77) && newline_flag) {
         out[idx2+4] = '\n';
         idx2++;
      }
   }
   left_over = len % 3;
   if (left_over == 1) {
      out[idx2] = charset[in[idx] >> 2];
      out[idx2+1] = charset[(in[idx] & 0x03) << 4];
      out[idx2+2] = '=';
      out[idx2+3] = '=';
      idx2 += 4;
   }
   else if (left_over == 2) {
      out[idx2] = charset[in[idx] >> 2];
      out[idx2+1] = charset[((in[idx] & 0x03) << 4) + (in[idx+1] >> 4)];
      out[idx2+2] = charset[(in[idx+1] & 0x0F) << 2];
      out[idx2+3] = '=';
      idx2 += 4;
   }
   out[idx2] = '\0';
   return(idx2);
}

#define UUID_STR_SIZE 37
void uuid_to_str(uint8_t* uuid, char* str, size_t size){
  if(size<37)
    return;
  sprintf(str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    uuid[0], uuid[1], uuid[2], uuid[3]
    , uuid[4], uuid[5]
    , uuid[6], uuid[7]
    , uuid[8], uuid[9]
    , uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

void _init_logs( void ){
  simplog.setLogFile(LOG_FILE);
  simplog.setLineWrap(false);
  simplog.setLogSilentMode(true);
  simplog.setLogDebugLevel(SIMPLOG_VERBOSE);
}

pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

void write_to_log(const char* fmt, ...){
  char tmp[10192];
	va_list args;
	va_start(args, fmt);
  vsprintf(tmp, fmt, args);
	va_end(args);
  pthread_mutex_lock(&mut);
  simplog.writeLog(SIMPLOG_INFO, tmp);
  pthread_mutex_unlock(&mut);
}

void init( void ){
  pid_t tid = gettid();
  write_to_log("audit writer thread, tid:%ld",
    tid);
}


void log_str(struct str_struct* data){
  write_to_log("%u-%u-%lu-\t%s",
    hostid, data->boot_id, data->event_id, data->str);
}

void log_link(struct link_struct* link){
  write_to_log("%u-%u-%lu-\tlink[%s]{%lu|%lu|%lu}",
    hostid, link->boot_id,link->event_id, link->name, link->inode_id, link->task_id, link->dir_id);
}

void log_unlink(struct unlink_struct* unlink){
  write_to_log("%u-%u-%lu-\tunlink[%s]{%lu|%lu|%lu}",
    hostid, unlink->boot_id, unlink->event_id, unlink->name, unlink->inode_id, unlink->task_id, unlink->dir_id);
}

void log_edge(struct edge_struct* edge){
    write_to_log("%u-%u-%lu-\t%s{%lu->%lu}%d",
      hostid, edge->boot_id, edge->event_id, edge_str[edge->type], edge->snd_id, edge->rcv_id, edge->allowed);
}

void log_task(struct task_prov_struct* task){
  write_to_log("%u-%u-%lu-\ttask[%lu]{%u|%u}",
    hostid, task->boot_id, task->event_id, task->node_id, task->uid, task->gid);
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

void log_inode(struct inode_prov_struct* inode){
  char sb_uuid[UUID_STR_SIZE];
  uuid_to_str(inode->sb_uuid, sb_uuid, UUID_STR_SIZE);
  write_to_log("%u-%u-%lu-\tinode[%s:%lu:%u:%s]{%u|%u|0X%04hhX}",
    hostid, inode->boot_id, inode->event_id, get_inode_type(inode->mode), inode->node_id, inode->version, sb_uuid, inode->uid, inode->gid, inode->mode);
}

void log_disc(struct disc_node_struct* node){
  write_to_log("%u-%u-%lu-\tdisclosed[%lu:%u]",
    hostid, node->boot_id, node->event_id, node->node_id, node->version);
}

void log_msg(struct msg_msg_struct* msg){
  write_to_log("%u-%u-%lu-\tmsg[%lu:%u]{%ld}",
    hostid, msg->boot_id, msg->event_id, msg->node_id, msg->version, msg->type);
}

void log_shm(struct shm_struct* shm){
  write_to_log("%u-%u-%lu-\tshm[%lu:%u]{0X%04hhX}",
    hostid, shm->boot_id, shm->event_id, shm->node_id, shm->version, shm->mode);
}


void log_sock(struct sock_struct* sock){
  write_to_log("%u-%u-%lu-\tsock[%lu]{%u|%u|%u}",
    hostid, sock->boot_id, sock->event_id, sock->node_id, sock->version, sock->type, sock->family, sock->protocol);
}

void log_address(struct address_struct* address){
  char host[NI_MAXHOST];
  char serv[NI_MAXSERV];
  int err;

  if(address->addr.sa_family == AF_INET || address->addr.sa_family == AF_INET6){
    err = getnameinfo(&(address->addr), address->length, host, NI_MAXHOST, serv, NI_MAXSERV, 0);
    if(err){
      printf("Error %d\n", err);
      return;
    }
    write_to_log("%u-%u-%lu-\taddress[%lu:%s:%s]{%u}",
      hostid, address->boot_id, address->event_id, address->sock_id, host, serv, address->addr.sa_family);
  }else if((address->addr).sa_family == AF_UNIX){
    write_to_log("%u-%u-%lu-\taddress[%lu:%s]{%u}",
      hostid, address->boot_id, address->event_id, address->sock_id, ((struct sockaddr_un*)&(address->addr))->sun_path, address->addr.sa_family);
  }else{
    write_to_log("%u-%u-%lu-\taddress[%lu:%s]{%u}",
      hostid, address->boot_id, address->event_id, address->sock_id, "type not handled", address->addr.sa_family);
  }
}

void log_file_name(struct file_name_struct* f_name){
  write_to_log("%u-%u-%lu-\tfile_name[%lu:%s]",
    hostid, f_name->boot_id, f_name->event_id, f_name->inode_id, f_name->name);
}

void log_ifc(struct ifc_context_struct* ifc){
  char buffer[4096];
  if(ifc->context.secrecy.size>0){
    label_to_str(ifc->context.secrecy.array, ifc->context.secrecy.size, buffer, 4096);
    write_to_log("%u-%u-%lu-\tsecrecy(%d)[%lu:%u]{%s}",
      hostid, ifc->boot_id, ifc->event_id, ifc->context.secrecy.size, ifc->node_id, ifc->version, buffer);
  }
  if(ifc->context.integrity.size>0){
    label_to_str(ifc->context.integrity.array, ifc->context.integrity.size, buffer, 4096);
    write_to_log("%u-%u-%lu-\tintegrity(%d)[%lu:%u]{%s}",
      hostid, ifc->boot_id, ifc->event_id, ifc->context.integrity.size, ifc->node_id, ifc->version, buffer);
  }
  if(ifc->context.secrecy_p.size>0){
    label_to_str(ifc->context.secrecy_p.array, ifc->context.secrecy_p.size, buffer, 4096);
    write_to_log("%u-%u-%lu-\tsecrecy_p(%d)[%lu:%u]{%s}",
      hostid, ifc->boot_id, ifc->event_id, ifc->context.secrecy_p.size, ifc->node_id, ifc->version, buffer);
  }
  if(ifc->context.secrecy_n.size>0){
    label_to_str(ifc->context.secrecy_n.array, ifc->context.secrecy_n.size, buffer, 4096);
    write_to_log("%u-%u-%lu-\tsecrecy_n(%d)[%lu:%u]{%s}",
      hostid, ifc->boot_id, ifc->event_id, ifc->context.secrecy_n.size, ifc->node_id, ifc->version, buffer);
  }
  if(ifc->context.integrity_p.size>0){
    label_to_str(ifc->context.integrity_p.array, ifc->context.integrity_p.size, buffer, 4096);
    write_to_log("%u-%u-%lu-\tintegrity_p(%d)[%lu:%u]{%s}",
      hostid, ifc->boot_id, ifc->event_id, ifc->context.integrity_p.size, ifc->node_id, ifc->version, buffer);
  }
  if(ifc->context.integrity_n.size>0){
    label_to_str(ifc->context.integrity_n.array, ifc->context.integrity_n.size, buffer, 4096);
    write_to_log("%u-%u-%lu-\tintegrity_n(%d)[%lu:%u]{%s}",
      hostid, ifc->boot_id, ifc->event_id, ifc->context.integrity_n.size, ifc->node_id, ifc->version, buffer);
  }
}

struct provenance_ops ops = {
  .init=init,
  .log_edge=log_edge,
  .log_task=log_task,
  .log_inode=log_inode,
  .log_str=log_str,
  .log_link=log_link,
  .log_unlink=log_unlink,
  .log_disc=log_disc,
  .log_msg=log_msg,
  .log_shm=log_shm,
  .log_sock=log_sock,
  .log_address=log_address,
  .log_file_name=log_file_name,
  .log_ifc=log_ifc
};

int main(void){
  int rc;
  hostid = gethostid();
	_init_logs();
  simplog.writeLog(SIMPLOG_INFO, "audit process pid: %d", getpid());
  rc = provenance_register(&ops);
  if(rc){
    simplog.writeLog(SIMPLOG_ERROR, "Failed registering audit operation.");
    exit(rc);
  }
  sleep(2);
  while(1) sleep(60);
  provenance_stop();
  return 0;
}
