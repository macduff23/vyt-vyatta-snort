/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
#include "debug.h"

#include "snort.h"



#ifdef DEBUG


int debuglevel = DEBUG_ALL;
char *DebugMessageFile = NULL;
int DebugMessageLine = 0;

int DebugThis(int level)
{
    if (!(level & GetDebugLevel()))
    {
        return 0;
    }
    
    return 1;
}

int GetDebugLevel (void)
{
    static int debug_init = 0;
    static int debug_level = 0;

    if(debug_init) {
        return debug_level;
    }

    if (getenv(DEBUG_VARIABLE))
        debug_level = atoi(getenv(DEBUG_VARIABLE));
    else
        debug_level = 0;

    debug_init = 1;
    return debug_level;
}


void DebugMessageFunc(int level, char *fmt, ...)
{
    va_list ap;
    char buf[STD_BUF+1];

    buf[STD_BUF]='\0';

    if (!(level & GetDebugLevel()))
    {
        return;
    }

    /* filename and line number information */
    if (DebugMessageFile != NULL)
        printf("%s:%d: ", DebugMessageFile, DebugMessageLine);

    va_start(ap, fmt);
        
    if(pv.daemon_flag)
    {
        vsnprintf(buf, STD_BUF, fmt, ap);
        buf[STD_BUF] = '\0';
        syslog(LOG_DAEMON | LOG_DEBUG, "%s", buf);
    }
    else
    {
        vprintf(fmt, ap);
    }

    va_end(ap);
}

#ifdef HAVE_WCHAR_H
void DebugWideMessageFunc(int level, wchar_t *fmt, ...)
{
    va_list ap;
    wchar_t buf[STD_BUF+1];


    if (!(level & GetDebugLevel()))
    {
        return;
    }
    buf[STD_BUF]= (wchar_t)0;
    
    /* filename and line number information */
    if (DebugMessageFile != NULL)
        printf("%s:%d: ", DebugMessageFile, DebugMessageLine);

    va_start(ap, fmt);
        
    if(pv.daemon_flag)
    {
#ifdef WIN32
        _vsnwprintf(buf, STD_BUF, fmt, ap);
#else
#ifdef HAVE_VSWPRINTF
        vswprintf(buf, STD_BUF, fmt, ap);
#endif
#endif
        //syslog(LOG_DAEMON | LOG_DEBUG, "%s", buf);
    }
    else
    {
#ifdef HAVE_WPRINTF
        vwprintf(fmt, ap);
#endif
    }

    va_end(ap);
}
#endif
#else
void DebugMessageFunc(int level, char *fmt, ...)
{
}
#ifdef HAVE_WCHAR_H
void DebugWideMessageFunc(int level, wchar_t *fmt, ...)
{
}
#endif
#endif /* DEBUG */
