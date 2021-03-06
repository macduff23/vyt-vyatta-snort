/****************************************************************************
 *
 * Copyright (C) 2005-2007 Sourcefire, Inc.
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
 
#ifndef SNORT_STREAM5_SESSION_H_
#define SNORT_STREAM5_SESSION_H_

#include "sfxhash.h"
#include "stream5_common.h"

typedef void(*Stream5SessionCleanup)(Stream5LWSession *ssn);

typedef struct _Stream5SessionCache
{
    SFXHASH *hashTable;
    u_int32_t timeout;
    u_int32_t max_sessions;
    u_int32_t cleanup_sessions;
    Stream5SessionCleanup cleanup_fcn;
} Stream5SessionCache;

void PrintSessionKey(SessionKey *);
Stream5SessionCache *InitLWSessionCache(int max_sessions,
                                        u_int32_t session_timeout,
                                        u_int32_t cleanup_sessions,
                                        u_int32_t cleanup_percent,
                                        Stream5SessionCleanup clean_fcn);
Stream5LWSession *GetLWSession(Stream5SessionCache *, Packet *, SessionKey *);
Stream5LWSession *GetLWSessionFromKey(Stream5SessionCache *, SessionKey *);
Stream5LWSession *NewLWSession(Stream5SessionCache *, Packet *, SessionKey *);
int DeleteLWSession(Stream5SessionCache *, Stream5LWSession *);
void PrintLWSessionCache(Stream5SessionCache *);
int PurgeLWSessionCache(Stream5SessionCache *);
int PruneLWSessionCache(Stream5SessionCache *,
                      u_int32_t thetime,
                      Stream5LWSession *save_me,
                      int memcheck);
int GetLWSessionCount(Stream5SessionCache *);
void GetLWPacketDirection(Packet *p, Stream5LWSession *ssn);
void FreeLWApplicationData(Stream5LWSession *ssn);

#endif /* SNORT_STREAM5_SESSION_H_ */

