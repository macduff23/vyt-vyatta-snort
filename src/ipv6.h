/****************************************************************************
 *
 * Copyright (C) 2007 Sourcefire, Inc.
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
 
#ifndef __IPV6_H__
#define __IPV6_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode.h"
#include "sfutil/sfxhash.h"

#define IP_PROTO_HOPOPTS    0
#define IP_PROTO_NONE       59
#define IP_PROTO_ROUTING    43
#define IP_PROTO_FRAGMENT   44
#define IP_PROTO_AH         51
#define IP_PROTO_DSTOPTS    60
#define IP_PROTO_ICMPV6     58
#define IP_PROTO_IPV6       41
#define IP_PROTO_IPIP       4

#define IPV6_FRAG_STR_ALERTED 1
#define IPV6_FRAG_NO_ALERT 0
#define IPV6_FRAG_ALERT 1
#define IPV6_FRAG_BAD_PKT 2
#define IPV6_MIN_TTL_EXCEEDED 3
#define IPV6_IS_NOT 4
#define IPV6_TRUNCATED_EXT 5
#define IPV6_TRUNCATED_FRAG 6
#define IPV6_TRUNCATED 7

#ifdef WORDS_BIGENDIAN
#define IP6F_OFF_MASK       0xfff8  /* mask out offset from _offlg */
#define IP6F_MORE_FRAG      0x0001  /* more-fragments flag */
#else   /* BYTE_ORDER == LITTLE_ENDIAN */
#define IP6F_OFF_MASK       0xf8ff  /* mask out offset from _offlg */
#define IP6F_MORE_FRAG      0x0100  /* more-fragments flag */
#endif


void ipv6_cleanup();
void ipv6_init();
int CheckIPV6Frag(char *, u_int32_t, Packet *);

#endif /* __IPV6_H__ */
