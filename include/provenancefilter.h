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
int provenance_reset_node_filter( void );

/*
* @filter pointer to contain filter to read
* read the current state of the node filter.
*/
int provenance_get_propagate_node_filter( uint32_t* filter );

/*
* @filter value of node filter
* set node provenance propagate filter.
*/
int provenance_add_propagate_node_filter( uint32_t filter );
int provenance_remove_propagate_node_filter( uint32_t filter );
int provenance_reset_propagate_node_filter( void );

/*
* @filter pointer to contain filter to read
* read the current state of the relation filter.
*/
int provenance_get_relation_filter( uint32_t* filter );

/*
* @filter value of node filter
* set relation provenance capture filter.
*/
int provenance_add_relation_filter( uint32_t filter );
int provenance_remove_relation_filter( uint32_t filter );
int provenance_reset_relation_filter( void );

/*
* @filter pointer to contain filter to read
* read the current state of the relation filter.
*/
int provenance_get_propagate_relation_filter( uint32_t* filter );

/*
* @filter value of node filter
* set relation provenance propagate filter.
*/
int provenance_add_propagate_relation_filter( uint32_t filter );
int provenance_remove_propagate_relation_filter( uint32_t filter );
int provenance_reset_propagate_relation_filter( void );

#endif
