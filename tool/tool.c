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

void usage( void ){
  printf("-h usage.\n");
  printf("-s print provenance capture state.\n");
  printf("-e <bool> enable/disable provenance capture.\n");
}

#define is_str_true(str) ( strcmp (str, "true") == 0)
#define is_str_false(str) ( strcmp (str, "false") == 0)

void enable( const char* str ){
  if(!is_str_true(str) && !is_str_false(str)){
    printf("Excepted a boolean, got %s.\n", str);
    return;
  }

  if(provenance_set_enable(is_str_true(str))<0)
    perror("Could not enable provenance capture");
}

void state( void ){
  printf("Provenance capture:\n");
  if(provenance_get_enable()){
    printf("- enabled;\n");
  }else{
    printf("- disabled;\n");
  }
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
    case 's':
      state();
      break;
    case 'e':
      enable(argv[2]);
      break;
    default:
      usage();
  }
  return 0;
}
