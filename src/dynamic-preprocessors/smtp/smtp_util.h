
/*
 * smtp_util.h
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
 * Copyright (C) 2005 Sourcefire Inc.
 *
 * Author: Andy  Mullican
 *
 */

#ifndef __SMTP_UTIL_H__
#define __SMTP_UTIL_H__

/* Boyer-Moore structure */
typedef struct tag_bm
{
    char *ptrn;
    int   plen;
    int  *skip;
    int  *shift;
} t_bm;

int    make_boyer_moore(t_bm *bm, char *ptrn, int plen);
void   cleanup_boyer_moore(t_bm *bm);
char * bm_search(char *buf, int blen, t_bm *bm);

char *    safe_strchr(char *buf, char c, u_int len);
void      copy_to_space(char *to, char *from, int to_len);

#endif  /*  __SMTP_UTIL_H__  */
