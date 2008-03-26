/* $Id$ */
/*
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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


#ifndef __UTIL_H__
#define __UTIL_H__

#define TIMEBUF_SIZE 26

#ifndef WIN32
#include <sys/time.h>
#include <sys/types.h>
#endif /* !WIN32 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRLCAT
#include "strlcatu.h"
#endif

#ifndef HAVE_STRLCPY
#include "strlcpyu.h"
#endif

/* specifies that a function does not return 
 * used for quieting Visual Studio warnings
 */
#ifdef _MSC_VER
#if _MSC_VER >= 1400
#define NORETURN __declspec(noreturn)
#else
#define NORETURN
#endif
#else
#define NORETURN
#endif

/* For Visual Studio compile warnings
 * SUPPRESS_WARNING - suppresses the next warning
 * only works with /analyze warnings (6000 and up)
 * DISABLE_WARNING - disables the specified warning
 * used for warnings under 6000
 * ENABLE_WARNING - enable the specified warning
 * used to enable warning that was disabled using DISABLE_WARNING
 */
#ifdef _MSC_VER
#if _MSC_VER >= 1400
//#define SUPPRESS_WARNING(x) __pragma(warning( suppress : x ))
//#define DISABLE_WARNING(x)  __pragma(warning( disable : x ))
//#define ENABLE_WARNING(x)   __pragma(warning( default : x ))
#define SUPPRESS_WARNING(x)
#define DISABLE_WARNING(x)
#define ENABLE_WARNING(x)
#else
#define SUPPRESS_WARNING(x)
#define DISABLE_WARNING(x)
#define ENABLE_WARNING(x)
#endif
#else
#define SUPPRESS_WARNING(x)
#define DISABLE_WARNING(x)
#define ENABLE_WARNING(x)
#endif

#include "sfsnprintfappend.h"

#define SNORT_SNPRINTF_SUCCESS 0
#define SNORT_SNPRINTF_TRUNCATION 1
#define SNORT_SNPRINTF_ERROR -1

#define SNORT_STRNCPY_SUCCESS 0
#define SNORT_STRNCPY_TRUNCATION 1
#define SNORT_STRNCPY_ERROR -1

#define SNORT_STRNLEN_ERROR -1

extern u_long netmasks[33];

/* Self preservation memory control struct */
typedef struct _SPMemControl
{
    unsigned long memcap;
    unsigned long mem_usage;
    void *control;
    int (*sp_func)(struct _SPMemControl *);

    unsigned long fault_count;

} SPMemControl;


int DisplayBanner();
void GetTime(char *);
int gmt2local(time_t);
void ts_print(register const struct timeval *, char *);
char *copy_argv(char **);
void strip(char *);
float CalcPct(float, float);
void ReadPacketsFromFile();
void GenHomenet(char *);
void InitNetmasks();
void InitBinFrag();
void GoDaemon();
void SignalWaitingParent();
void CheckLogDir();
char *read_infile(char *);
void InitProtoNames();
void CleanupProtoNames();
void PrintError(char *);
void ErrorMessage(const char *, ...);
void LogMessage(const char *, ...);
NORETURN void FatalError(const char *, ...);
NORETURN void FatalPrintError(char *);
void CreatePidFile(char *);
void ClosePidFile();
void SetUidGid(void);
void SetChroot(char *, char **);
void DropStats(int);
void GenObfuscationMask(char *);
void *SPAlloc(unsigned long, struct _SPMemControl *);
int SnortSnprintf(char *, size_t, const char *, ...);
int SnortSnprintfAppend(char *, size_t, const char *, ...);
char *SnortStrdup(char *);
int SnortStrncpy(char *, const char *, size_t);
int SnortStrnlen(char *, int);
void *SnortAlloc(unsigned long);
void *SnortAlloc2(size_t, const char *, ...);
char *CurrentWorkingDir(void);
char *GetAbsolutePath(char *dir);
char *StripPrefixDir(char *prefix, char *dir);
void DefineAllIfaceVars();
void DefineIfaceVar(char *,u_char *, u_char *);
#ifdef TIMESTATS
void DropHourlyStats();
#endif


#endif /*__UTIL_H__*/
