/*
* CamFlow userspace provenance tool
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
#define _XOPEN_SOURCE 500
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/camflow.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "provenancelib.h"
#include "provenancefilter.h"

void usage( void ){
  printf("-h usage.\n");
  printf("-s print provenance capture state.\n");
  printf("-e <bool> enable/disable provenance capture.\n");
  printf("-a <bool> activate/deactivate whole-system provenance capture.\n");
  printf("-d <bool> activate/deactivate directories provenance capture.\n");
  printf("-f <filename> display provenance info of a file.\n");
  printf("-t <bool> <filename> [depth] activate/deactivate tracking of a file.\n");
  printf("-o <bool> <filename> mark/unmark a file as opaque.\n");
}

#define is_str_true(str) ( strcmp (str, "true") == 0)
#define is_str_false(str) ( strcmp (str, "false") == 0)

void enable( const char* str ){
  if(!is_str_true(str) && !is_str_false(str)){
    printf("Excepted a boolean, got %s.\n", str);
    return;
  }

  if(provenance_set_enable(is_str_true(str))<0)
    perror("Could not enable/disable provenance capture");
}

void all( const char* str ){
  if(!is_str_true(str) && !is_str_false(str)){
    printf("Excepted a boolean, got %s.\n", str);
    return;
  }

  if(provenance_set_all(is_str_true(str))<0)
    perror("Could not activate/deactivate whole-system provenance capture");
}

void dir( const char* str ){
  int err;
  if(!is_str_true(str) && !is_str_false(str)){
    printf("Excepted a boolean, got %s.\n", str);
    return;
  }

  if(is_str_true(str)){
    err = provenance_add_node_filter(MSG_INODE_DIRECTORY);
  }else{
    err = provenance_remove_node_filter(MSG_INODE_DIRECTORY);
  }

  if(err<0){
    perror("Could not activate/deactivate directories provenance capture");
  }
}

void state( void ){
  uint32_t filter=0;
  printf("Provenance capture:\n");
  if(provenance_get_enable()){
    printf("- capture enabled;\n");
  }else{
    printf("- capture disabled;\n");
  }
  if( provenance_get_all() ){
    printf("- all enabled;\n");
  }else{
    printf("- all disabled;\n");
  }

  provenance_get_node_filter(&filter);
  printf("\nNode filter (%0x):\n", filter);
  if( (filter&MSG_INODE_DIRECTORY) == 0 ){
    printf("- directories provenance captured;\n");
  }else{
    printf("- directories provenance not captured;\n");
  }
}

void print_version(){
  printf("CamFlow %s\n", CAMFLOW_VERSION_STR);
}

int main(int argc, char *argv[]){
  int i;
  tag_t tag;

  if(argc < 2){
    usage();
    exit(-1);
  }
  // do it properly, but that will do for now
  switch(argv[1][1]){
    case 'h':
      usage();
      break;
    case 'v':
      print_version();
      break;
    case 's':
      state();
      break;
    case 'e':
      enable(argv[2]);
      break;
    case 'a':
      all(argv[2]);
      break;
    case 'd':
      dir(argv[2]);
      break;
    default:
      usage();
  }
  return 0;
}
