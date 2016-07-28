/*
*
* provenanceutils.c
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

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "provenanceutils.h"

static const char map[16+1] = "0123456789ABCDEF";

size_t hexify(uint8_t *in, size_t in_size, char *out, size_t out_size)
{
    if (in_size == 0 || out_size == 0) return 0;

    size_t bytes_written = 0;
    size_t i = 0;
    while(i < in_size && (i*2 + (2+1)) <= out_size)
    {
        uint8_t high_nibble = (in[i] & 0xF0) >> 4;
        *out = map[high_nibble];
        out++;

        uint8_t low_nibble = in[i] & 0x0F;
        *out = map[low_nibble];
        out++;

        i++;

        bytes_written += 2;
    }
    *out = '\0';

    return bytes_written;
}
