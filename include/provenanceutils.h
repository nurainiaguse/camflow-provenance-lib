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
static const char RL_STR_MMAP []                  = "mmap";
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
    case RL_MMAP:
      return RL_STR_MMAP;
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
    default:
      return RL_STR_UNKNOWN;
  }
}

#endif /* __PROVENANCEUTILS_H */
