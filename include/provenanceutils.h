/*
*
* provenanceutils.h
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

#define HEXIFY_OUTPUT_LENGTH(in) (in*2+1)
size_t hexify(uint8_t *in, size_t in_size, char *out, size_t out_size);
#define ENCODE64_OUTPUT_LENGTH(in) (4 * ((in + 2) / 3) + 1)
int base64encode(const void* data_buf, size_t dataLength, char* result, size_t resultSize);

#endif /* __PROVENANCEUTILS_H */
