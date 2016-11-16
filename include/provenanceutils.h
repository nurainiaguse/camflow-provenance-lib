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
#ifndef __PROVENANCEUTILS_H
#define __PROVENANCEUTILS_H

#include <sys/socket.h>
#include <stdbool.h>
#include <linux/provenance.h>
#include <zlib.h>
#include <arpa/inet.h>

#define hexifyBound(in) (in*2+1)
size_t hexify(uint8_t *in, size_t in_size, char *out, size_t out_size);
#define encode64Bound(in) (4 * ((in + 2) / 3) + 1)
int base64encode(const void* data_buf, size_t dataLength, char* result, size_t resultSize);
#define compress64encodeBound(in) encode64Bound(compressBound(in))
int compress64encode(const char* in, size_t inlen, char* out, size_t outlen);

#define PROV_ID_STR_LEN encode64Bound(PROV_IDENTIFIER_BUFFER_LENGTH)
#define ID_ENCODE base64encode
#define TAINT_ENCODE hexify
#define TAINT_STR_LEN hexifyBound(PROV_N_BYTES)

static const char RL_STR_UNKNOWN []               = "unknown";
static const char RL_STR_READ []                  = "read";
static const char RL_STR_WRITE []                 = "write";
static const char RL_STR_CREATE []                = "create";
static const char RL_STR_CHANGE []                = "change";
static const char RL_STR_MMAP_WRITE []            = "mmap_write";
static const char RL_STR_BIND []                  = "bind";
static const char RL_STR_CONNECT []               = "connect";
static const char RL_STR_LISTEN []                = "listen";
static const char RL_STR_ACCEPT []                = "accept";
static const char RL_STR_OPEN []                  = "open";
static const char RL_STR_VERSION []               = "version_entity";
static const char RL_STR_LINK []                  = "link";
static const char RL_STR_NAMED []                 = "named";
static const char RL_STR_IFC []                   = "ifc";
static const char RL_STR_EXEC []                  = "exec";
static const char RL_STR_CLONE []                 = "clone";
static const char RL_STR_VERSION_PROCESS []       = "version_activity";
static const char RL_STR_SEARCH []                = "search";
static const char RL_STR_MMAP_READ []             = "mmap_read";
static const char RL_STR_MMAP_EXEC []             = "mmap_exec";
static const char RL_STR_SND []                   = "send";
static const char RL_STR_RCV []                   = "receive";
static const char RL_STR_PERM_READ[]              = "perm_read";
static const char RL_STR_PERM_WRITE[]             = "perm_write";
static const char RL_STR_PERM_EXEC[]              = "perm_exec";

static inline const char* relation_str(uint64_t type){
  switch(type){
    case RL_READ:
      return RL_STR_READ;
    case RL_WRITE:
      return RL_STR_WRITE;
    case RL_CREATE:
      return RL_STR_CREATE;
    case RL_CHANGE:
      return RL_STR_CHANGE;
    case RL_MMAP_WRITE:
      return RL_STR_MMAP_WRITE;
    case RL_BIND:
      return RL_STR_BIND;
    case RL_CONNECT:
      return RL_STR_CONNECT;
    case RL_LISTEN:
      return RL_STR_LISTEN;
    case RL_ACCEPT:
      return RL_STR_ACCEPT;
    case RL_OPEN:
      return RL_STR_OPEN;
    case RL_VERSION:
      return RL_STR_VERSION;
    case RL_LINK:
      return RL_STR_LINK;
    case RL_NAMED:
      return RL_STR_NAMED;
    case RL_IFC:
      return RL_STR_IFC;
    case RL_EXEC:
      return RL_STR_EXEC;
    case RL_CLONE:
      return RL_STR_CLONE;
    case RL_VERSION_PROCESS:
      return RL_STR_VERSION_PROCESS;
    case RL_SEARCH:
      return RL_STR_SEARCH;
    case RL_MMAP_READ:
      return RL_STR_MMAP_READ;
    case RL_MMAP_EXEC:
      return RL_STR_MMAP_EXEC;
    case RL_SND:
      return RL_STR_SND;
    case RL_RCV:
      return RL_STR_RCV;
    case RL_PERM_READ:
      return RL_STR_PERM_READ;
    case RL_PERM_WRITE:
      return RL_STR_PERM_WRITE;
    case RL_PERM_EXEC:
      return RL_STR_PERM_EXEC;
    default:
      return RL_STR_UNKNOWN;
  }
}

#define MATCH_AND_RETURN(str1, str2, v) if(strcmp(str1, str2)==0) return v

static inline const uint64_t relation_id(char* str){
  MATCH_AND_RETURN(str, RL_STR_READ, RL_READ);
  MATCH_AND_RETURN(str, RL_STR_WRITE, RL_WRITE);
  MATCH_AND_RETURN(str, RL_STR_CREATE, RL_CREATE);
  MATCH_AND_RETURN(str, RL_STR_CHANGE, RL_CHANGE);
  MATCH_AND_RETURN(str, RL_STR_MMAP_WRITE, RL_MMAP_WRITE);
  MATCH_AND_RETURN(str, RL_STR_BIND, RL_BIND);
  MATCH_AND_RETURN(str, RL_STR_CONNECT, RL_CONNECT);
  MATCH_AND_RETURN(str, RL_STR_LISTEN, RL_LISTEN);
  MATCH_AND_RETURN(str, RL_STR_ACCEPT, RL_ACCEPT);
  MATCH_AND_RETURN(str, RL_STR_OPEN, RL_OPEN);
  MATCH_AND_RETURN(str, RL_STR_VERSION, RL_VERSION);
  MATCH_AND_RETURN(str, RL_STR_LINK, RL_LINK);
  MATCH_AND_RETURN(str, RL_STR_NAMED, RL_NAMED);
  MATCH_AND_RETURN(str, RL_STR_IFC, RL_IFC);
  MATCH_AND_RETURN(str, RL_STR_EXEC, RL_EXEC);
  MATCH_AND_RETURN(str, RL_STR_CLONE, RL_CLONE);
  MATCH_AND_RETURN(str, RL_STR_VERSION_PROCESS, RL_VERSION_PROCESS);
  MATCH_AND_RETURN(str, RL_STR_SEARCH, RL_SEARCH);
  MATCH_AND_RETURN(str, RL_STR_MMAP_READ, RL_MMAP_READ);
  MATCH_AND_RETURN(str, RL_STR_MMAP_EXEC, RL_MMAP_EXEC);
  MATCH_AND_RETURN(str, RL_STR_SND, RL_SND);
  MATCH_AND_RETURN(str, RL_STR_RCV, RL_RCV);
  MATCH_AND_RETURN(str, RL_STR_PERM_READ, RL_PERM_READ);
  MATCH_AND_RETURN(str, RL_STR_PERM_WRITE, RL_PERM_WRITE);
  MATCH_AND_RETURN(str, RL_STR_PERM_EXEC, RL_PERM_EXEC);
  return 0;
}

static const char MSG_STR_UNKNOWN[]=           "unknown";
static const char MSG_STR_STR[]=               "string";
static const char MSG_STR_RELATION[]=          "relation";
static const char MSG_STR_TASK[]=              "task";
static const char MSG_STR_INODE_UNKNOWN[]=     "inode_unknown";
static const char MSG_STR_INODE_LINK[]=        "link";
static const char MSG_STR_INODE_FILE[]=        "file";
static const char MSG_STR_INODE_DIRECTORY[]=   "directory";
static const char MSG_STR_INODE_CHAR[]=        "char";
static const char MSG_STR_INODE_BLOCK[]=       "block";
static const char MSG_STR_INODE_FIFO[]=        "fifo";
static const char MSG_STR_INODE_SOCKET[]=      "socket";
static const char MSG_STR_MSG[]=               "msg";
static const char MSG_STR_SHM[]=               "shm";
static const char MSG_STR_SOCK[]=              "sock";
static const char MSG_STR_ADDR[]=              "address";
static const char MSG_STR_SB[]=                "sb";
static const char MSG_STR_FILE_NAME[]=         "file_name";
static const char MSG_STR_IFC[]=               "ifc";
static const char MSG_STR_DISC_ENTITY[]=       "disc_entity";
static const char MSG_STR_DISC_ACTIVITY[]=     "disc_activity";
static const char MSG_STR_DISC_AGENT[]=        "disc_agent";
static const char MSG_STR_DISC_NODE[]=         "disc_node";
static const char MSG_STR_PACKET[]=            "packet";
static const char MSG_STR_INODE_MMAP[]=        "mmaped_file";

static inline const uint64_t node_id(char* str){
  MATCH_AND_RETURN(str, MSG_STR_TASK, ACT_TASK);
  MATCH_AND_RETURN(str, MSG_STR_INODE_UNKNOWN, ENT_INODE_UNKNOWN);
  MATCH_AND_RETURN(str, MSG_STR_INODE_LINK, ENT_INODE_LINK);
  MATCH_AND_RETURN(str, MSG_STR_INODE_FILE, ENT_INODE_FILE);
  MATCH_AND_RETURN(str, MSG_STR_INODE_DIRECTORY, ENT_INODE_DIRECTORY);
  MATCH_AND_RETURN(str, MSG_STR_INODE_CHAR, ENT_INODE_CHAR);
  MATCH_AND_RETURN(str, MSG_STR_INODE_BLOCK, ENT_INODE_BLOCK);
  MATCH_AND_RETURN(str, MSG_STR_INODE_FIFO, ENT_INODE_FIFO);
  MATCH_AND_RETURN(str, MSG_STR_INODE_SOCKET, ENT_INODE_SOCKET);
  MATCH_AND_RETURN(str, MSG_STR_INODE_MMAP, ENT_INODE_MMAP);
  MATCH_AND_RETURN(str, MSG_STR_MSG, ENT_MSG);
  MATCH_AND_RETURN(str, MSG_STR_SHM, ENT_SHM);
  MATCH_AND_RETURN(str, MSG_STR_ADDR, ENT_ADDR);
  MATCH_AND_RETURN(str, MSG_STR_SB, ENT_SBLCK);
  MATCH_AND_RETURN(str, MSG_STR_FILE_NAME, ENT_FILE_NAME);
  MATCH_AND_RETURN(str, MSG_STR_IFC, ENT_IFC);
  MATCH_AND_RETURN(str, MSG_STR_DISC_ENTITY, ENT_DISC);
  MATCH_AND_RETURN(str, MSG_STR_DISC_ACTIVITY, ACT_DISC);
  MATCH_AND_RETURN(str, MSG_STR_DISC_AGENT, AGT_DISC);
  MATCH_AND_RETURN(str, MSG_STR_PACKET, ENT_PACKET);
  return 0;
}

static inline const char* node_str(uint64_t type){
  switch(type){
    case ENT_STR:
      return MSG_STR_STR;
    case ACT_TASK:
      return MSG_STR_TASK;
    case ENT_INODE_UNKNOWN:
      return MSG_STR_INODE_UNKNOWN;
    case ENT_INODE_LINK:
      return MSG_STR_INODE_LINK;
    case ENT_INODE_FILE:
      return MSG_STR_INODE_FILE;
    case ENT_INODE_DIRECTORY:
      return MSG_STR_INODE_DIRECTORY;
    case ENT_INODE_CHAR:
      return MSG_STR_INODE_CHAR;
    case ENT_INODE_BLOCK:
      return MSG_STR_INODE_BLOCK;
    case ENT_INODE_FIFO:
      return MSG_STR_INODE_FIFO;
    case ENT_INODE_SOCKET:
      return MSG_STR_INODE_SOCKET;
    case ENT_INODE_MMAP:
      return MSG_STR_INODE_MMAP;
    case ENT_MSG:
      return MSG_STR_MSG;
    case ENT_SHM:
      return MSG_STR_SHM;
    case ENT_ADDR:
      return MSG_STR_ADDR;
    case ENT_SBLCK:
      return MSG_STR_SB;
    case ENT_FILE_NAME:
      return MSG_STR_FILE_NAME;
    case ENT_IFC:
      return MSG_STR_IFC;
    case ENT_DISC:
      return MSG_STR_DISC_ENTITY;
    case ACT_DISC:
      return MSG_STR_DISC_ACTIVITY;
    case AGT_DISC:
      return MSG_STR_DISC_AGENT;
    case ENT_PACKET:
      return MSG_STR_PACKET;
    default:
      return MSG_STR_UNKNOWN;
  }
}

#define DECIMAL 10
#define OCTAL   8
#define HEX     16
char *ulltoa (uint64_t value, char *string, int radix);
char *utoa (uint32_t value, char *string, int radix);
char *itoa(int32_t a, char *string, int radix);
char *lltoa(int64_t a, char *string, int radix);

// just wrap inet_pton
static inline uint32_t ipv4str_to_uint32(const char* str){
  struct in_addr addr;
  inet_pton(AF_INET, str, &addr);
  return (uint32_t)addr.s_addr;
}

static __thread char __addr[INET_ADDRSTRLEN];
// just wrap inet_ntop
static inline const char* uint32_to_ipv4str(uint32_t v){
  inet_ntop(AF_INET, &v, __addr, INET_ADDRSTRLEN);
  return __addr;
}

union mask{
  uint32_t value;
  uint8_t buffer[4];
};

#define reverse_byte(b) (b * 0x0202020202ULL & 0x010884422010ULL) % 1023

static inline uint32_t uint32_to_ipv4mask(uint32_t n){
  int i;
  union mask m;
  if(n>32){
    return 0xFFFFFFFF;
  }

  m.value = (uint32_t)(((uint64_t)1 << n) - 1);
  for(i=0; i<4; i++){
    m.buffer[i] = reverse_byte(m.buffer[i]);
  }
  return m.value;
}

static inline uint8_t count_set_bits(uint32_t n){
  uint8_t count = 0;
  while(n)
  {
    count += n & 1;
    n >>= 1;
  }
  return count;
}

#endif /* __PROVENANCEUTILS_H */
