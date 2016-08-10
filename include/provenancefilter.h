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

#ifndef __PROVENANCEFILTER_H
#define __PROVENANCEFILTER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <linux/provenance.h>


/*
* @filter pointer to contain filter to read
* read the current state of the node filter.
*/
int provenance_get_node_filter( uint32_t* filter );

/*
* @filter value of node filter
* set node provenance capture filter.
*/
int provenance_add_node_filter( uint32_t filter );
int provenance_remove_node_filter( uint32_t filter );

/*
* @filter pointer to contain filter to read
* read the current state of the edge filter.
*/
int provenance_get_edge_filter( uint32_t* filter );

/*
* @filter value of node filter
* set edge provenance capture filter.
*/
int provenance_add_edge_filter( uint32_t filter );
int provenance_remove_edge_filter( uint32_t filter );

#endif
