/****************************************************************************
 *
 * Copyright (C) 2004-2007 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/
 
#ifndef __SNORT_PKT_HEADER_H__
#define __SNORT_PKT_HEADER_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/time.h>
#endif

#include <stdlib.h>
#include <time.h>
#include <sys/types.h>


/* we must use fixed size of 32 bits, because on-disk
 * format of savefiles uses 32-bit tv_sec (and tv_usec)
 */
struct pcap_timeval {
    u_int32_t tv_sec;      /* seconds */
    u_int32_t tv_usec;     /* microseconds */
};

/* this is equivalent to the pcap pkthdr struct, but we need one for
 * portability once we introduce the pa_engine code 
 */
typedef struct _SnortPktHeader
{
    struct pcap_timeval ts;/* packet timestamp */
    u_int32_t caplen;      /* packet capture length */
    u_int32_t pktlen;      /* packet "real" length */
} SnortPktHeader;


#endif // __SNORT_PKT_HEADER_H__
