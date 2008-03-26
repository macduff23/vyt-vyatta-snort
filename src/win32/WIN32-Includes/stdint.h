/* $Id$ */
/*
** Copyright (C) 1998-2003 Chris Reid <chris.reid@codecraftconsultants.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


#ifndef __STDINT_H__
#define __STDINT_H__

/*
 * Microsoft Visual C++ 6.0 doesn't support conversion from
 * "unsigned __uint64" to "signed __uint64", as is necessary
 * in the performance code (perf*.c/h).  So, we'll use
 * signed values instead.
 */

#if defined(__GNUC__) && !defined(__int64)
#define __in64 long long
#endif

typedef __int8             int8_t;
typedef __int16            int16_t;
typedef __int32            int32_t;
typedef __int64            int64_t;

typedef unsigned __int8    uint8_t;
typedef unsigned __int16   uint16_t;
typedef unsigned __int32   uint32_t;
typedef   signed __int64   uint64_t;

#ifndef HAVE_U_INT8_T
typedef uint8_t            u_int8_t;
#define HAVE_U_INT8_T
#endif
#ifndef HAVE_U_INT16_T
typedef uint16_t           u_int16_t;
#define HAVE_U_INT16_T
#endif
#ifndef HAVE_U_INT32_T
typedef uint32_t           u_int32_t;
#define HAVE_U_INT32_T
#endif
#define UINT64             uint64_t
typedef uint64_t           uint64;

#define UINT32_MAX         (4294967295U)
#endif

