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

#define hexifyBound(in) (in*2+1)
size_t hexify(uint8_t *in, size_t in_size, char *out, size_t out_size);
#define encode64Bound(in) (4 * ((in + 2) / 3) + 1)
int base64encode(const void* data_buf, size_t dataLength, char* result, size_t resultSize);
#define compress64encodeBound(in) encode64Bound(compressBound(in))
int compress64encode(const char* in, size_t inlen, char* out, size_t outlen);

#define PROV_ID_STR_LEN encode64Bound(PROV_IDENTIFIER_BUFFER_LENGTH)
#define ID_ENCODE base64encode

static const char RL_STR_UNKNOWN []               = "unknown";
static const char RL_STR_READ []                  = "read";
static const char RL_STR_WRITE []                 = "write";
static const char RL_STR_CREATE []                = "create";
static const char RL_STR_PASS []                  = "pass";
static const char RL_STR_CHANGE []                = "change";
static const char RL_STR_MMAP_WRITE []            = "mmap_write";
static const char RL_STR_ATTACH []                = "attach";
static const char RL_STR_ASSOCIATE []             = "associate";
static const char RL_STR_BIND []                  = "bind";
static const char RL_STR_CONNECT []               = "connect";
static const char RL_STR_LISTEN []                = "listen";
static const char RL_STR_ACCEPT []                = "accept";
static const char RL_STR_OPEN []                  = "open";
static const char RL_STR_PARENT []                = "parent";
static const char RL_STR_VERSION []               = "version";
static const char RL_STR_LINK []                  = "link";
static const char RL_STR_NAMED []                 = "named";
static const char RL_STR_IFC []                   = "ifc";
static const char RL_STR_EXEC []                  = "exec";
static const char RL_STR_FORK []                  = "fork";
static const char RL_STR_VERSION_PROCESS []       = "version";
static const char RL_STR_SEARCH []                = "search";
static const char RL_STR_MMAP_READ []             = "mmap_read";
static const char RL_STR_MMAP_EXEC []             = "mmap_exec";

static inline const char* relation_str(uint32_t type){
  switch(type){
    case RL_READ:
      return RL_STR_READ;
    case RL_WRITE:
      return RL_STR_WRITE;
    case RL_CREATE:
      return RL_STR_CREATE;
    case RL_PASS:
      return RL_STR_PASS;
    case RL_CHANGE:
      return RL_STR_CHANGE;
    case RL_MMAP_WRITE:
      return RL_STR_MMAP_WRITE;
    case RL_ATTACH:
      return RL_STR_ATTACH;
    case RL_ASSOCIATE:
      return RL_STR_ASSOCIATE;
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
    case RL_PARENT:
      return RL_STR_PARENT;
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
    case RL_FORK:
      return RL_STR_FORK;
    case RL_VERSION_PROCESS:
      return RL_STR_VERSION_PROCESS;
    case RL_SEARCH:
      return RL_STR_SEARCH;
    case RL_MMAP_READ:
      return RL_STR_MMAP_READ;
    case RL_MMAP_EXEC:
      return RL_STR_MMAP_EXEC;
    default:
      return RL_STR_UNKNOWN;
  }
}

#define MATCH_AND_RETURN(str1, str2, v) if(strcmp(str1, str2)==0) return v

static inline const int relation_id(char* str){
  MATCH_AND_RETURN(str, RL_STR_READ, RL_READ);
  MATCH_AND_RETURN(str, RL_STR_WRITE, RL_WRITE);
  MATCH_AND_RETURN(str, RL_STR_CREATE, RL_CREATE);
  MATCH_AND_RETURN(str, RL_STR_PASS, RL_PASS);
  MATCH_AND_RETURN(str, RL_STR_CHANGE, RL_CHANGE);
  MATCH_AND_RETURN(str, RL_STR_MMAP_WRITE, RL_MMAP_WRITE);
  MATCH_AND_RETURN(str, RL_STR_ATTACH, RL_ATTACH);
  MATCH_AND_RETURN(str, RL_STR_ASSOCIATE, RL_ASSOCIATE);
  MATCH_AND_RETURN(str, RL_STR_BIND, RL_BIND);
  MATCH_AND_RETURN(str, RL_STR_CONNECT, RL_CONNECT);
  MATCH_AND_RETURN(str, RL_STR_LISTEN, RL_LISTEN);
  MATCH_AND_RETURN(str, RL_STR_ACCEPT, RL_ACCEPT);
  MATCH_AND_RETURN(str, RL_STR_OPEN, RL_OPEN);
  MATCH_AND_RETURN(str, RL_STR_PARENT, RL_PARENT);
  MATCH_AND_RETURN(str, RL_STR_VERSION, RL_VERSION);
  MATCH_AND_RETURN(str, RL_STR_LINK, RL_LINK);
  MATCH_AND_RETURN(str, RL_STR_NAMED, RL_NAMED);
  MATCH_AND_RETURN(str, RL_STR_IFC, RL_IFC);
  MATCH_AND_RETURN(str, RL_STR_EXEC, RL_EXEC);
  MATCH_AND_RETURN(str, RL_STR_FORK, RL_FORK);
  MATCH_AND_RETURN(str, RL_STR_VERSION_PROCESS, RL_VERSION_PROCESS);
  MATCH_AND_RETURN(str, RL_STR_SEARCH, RL_SEARCH);
  MATCH_AND_RETURN(str, RL_STR_MMAP_READ, RL_MMAP_READ);
  MATCH_AND_RETURN(str, RL_STR_MMAP_EXEC, RL_MMAP_EXEC);
  return 0;
}

#define MSG_STR_STR               "string"
#define MSG_STR_RELATION          "relation"
#define MSG_STR_TASK              "task"
#define MSG_STR_INODE_UNKNOWN     "inode_unknown"
#define MSG_STR_INODE_LINK        "link"
#define MSG_STR_INODE_FILE        "file"
#define MSG_STR_INODE_DIRECTORY   "directory"
#define MSG_STR_INODE_CHAR        "char"
#define MSG_STR_INODE_BLOCK       "block"
#define MSG_STR_INODE_FIFO        "fifo"
#define MSG_STR_INODE_SOCKET      "socket"
#define MSG_STR_MSG               "msg"
#define MSG_STR_SHM               "shm"
#define MSG_STR_SOCK              "sock"
#define MSG_STR_ADDR              "address"
#define MSG_STR_SB                "sb"
#define MSG_STR_FILE_NAME         "file_name"
#define MSG_STR_IFC               "ifc"
#define MSG_STR_DISC_ENTITY       "disc_entity"
#define MSG_STR_DISC_ACTIVITY     "disc_activity"
#define MSG_STR_DISC_AGENT        "disc_agent"
#define MSG_STR_DISC_NODE         "disc_node"

static inline const int node_id(char* str){
  MATCH_AND_RETURN(str, MSG_STR_TASK, MSG_TASK);
  MATCH_AND_RETURN(str, MSG_STR_INODE_UNKNOWN, MSG_INODE_UNKNOWN);
  MATCH_AND_RETURN(str, MSG_STR_INODE_LINK, MSG_INODE_LINK);
  MATCH_AND_RETURN(str, MSG_STR_INODE_FILE, MSG_INODE_FILE);
  MATCH_AND_RETURN(str, MSG_STR_INODE_DIRECTORY, MSG_INODE_DIRECTORY);
  MATCH_AND_RETURN(str, MSG_STR_INODE_CHAR, MSG_INODE_CHAR);
  MATCH_AND_RETURN(str, MSG_STR_INODE_BLOCK, MSG_INODE_BLOCK);
  MATCH_AND_RETURN(str, MSG_STR_INODE_FIFO, MSG_INODE_FIFO);
  MATCH_AND_RETURN(str, MSG_STR_INODE_SOCKET, MSG_INODE_SOCKET);
  MATCH_AND_RETURN(str, MSG_STR_MSG, MSG_MSG);
  MATCH_AND_RETURN(str, MSG_STR_SHM, MSG_SHM);
  MATCH_AND_RETURN(str, MSG_STR_SOCK, MSG_SOCK);
  MATCH_AND_RETURN(str, MSG_STR_ADDR, MSG_ADDR);
  MATCH_AND_RETURN(str, MSG_STR_SB, MSG_SB);
  MATCH_AND_RETURN(str, MSG_STR_FILE_NAME, MSG_FILE_NAME);
  MATCH_AND_RETURN(str, MSG_STR_IFC, MSG_IFC);
  MATCH_AND_RETURN(str, MSG_STR_DISC_ENTITY, MSG_DISC_ENTITY);
  MATCH_AND_RETURN(str, MSG_STR_DISC_ACTIVITY, MSG_DISC_ACTIVITY);
  MATCH_AND_RETURN(str, MSG_STR_DISC_AGENT, MSG_DISC_AGENT);
  MATCH_AND_RETURN(str, MSG_STR_DISC_NODE, MSG_DISC_NODE);
  return 0;
}

#endif /* __PROVENANCEUTILS_H */
