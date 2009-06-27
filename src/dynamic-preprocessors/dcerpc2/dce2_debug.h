/****************************************************************************
 * Copyright (C) 2008-2009 Sourcefire, Inc.
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
 **************************************************************************** 
 * Provides macros and functions for debugging the preprocessor.
 * If Snort is not configured to do debugging, macros are empty.
 *
 * 8/17/2008 - Initial implementation ... Todd Wease <twease@sourcefire.com>
 *
 ****************************************************************************/

#ifndef _DCE2_DEBUG_H_
#define _DCE2_DEBUG_H_

#include "debug.h"
#include "sf_types.h"
#include <stdio.h>

/********************************************************************
 * Public function prototypes
 ********************************************************************/
/* Don't use these directly - use the macros defined below */
int DCE2_DebugThis(int);
void DCE2_DebugMsg(int, const char *, ...);
uint32_t DCE2_GetDebugLevel(void);

/********************************************************************
 * Macros
 ********************************************************************/
#define DCE2_DEBUG_VARIABLE   "DCE2_DEBUG"

#define DCE2_DEBUG__NONE      0x00000000
#define DCE2_DEBUG__ROPTIONS  0x00000001
#define DCE2_DEBUG__CONFIG    0x00000002
#define DCE2_DEBUG__MAIN      0x00000004
#define DCE2_DEBUG__SMB       0x00000008
#define DCE2_DEBUG__CO        0x00000010
#define DCE2_DEBUG__EVENT     0x00000020
#define DCE2_DEBUG__MEMORY    0x00000040
#define DCE2_DEBUG__HTTP      0x00000080
#define DCE2_DEBUG__CL        0x00000100
#define DCE2_DEBUG__ALL       0xffffffff

#define DCE2_DEBUG__START_MSG  "DCE/RPC Start ********************************************"
#define DCE2_DEBUG__END_MSG    "DCE/RPC End **********************************************"

#if defined(DEBUG) && !defined(WIN32)   /* No debugging code in Windows */
#include <assert.h>
#define DCE2_ASSERT(code)             assert(code)
#define DCE2_DEBUG_MSG(level, ...)    DCE2_DebugMsg(level, __VA_ARGS__)
#define DCE2_DEBUG_VAR(code)          code
#define DCE2_DEBUG_CODE(level, code)  { if (DCE2_DebugThis(level)) { code } }
#else
#define DCE2_ASSERT(code)
#ifdef WIN32
/* Windows no likey "..." in a macro */
static INLINE void DCE2_DEBUG_MSG(int level, ...) { level = 0; }  /* Just set it to avoid warning */
#else
#define DCE2_DEBUG_MSG(level, ...)
#endif  /* WIN32 */
#define DCE2_DEBUG_VAR(code)
#define DCE2_DEBUG_CODE(level, code)
#endif  /* defined(DEBUG) && !defined(WIN32) */


#endif  /* _DCE2_DEBUG_H_ */

