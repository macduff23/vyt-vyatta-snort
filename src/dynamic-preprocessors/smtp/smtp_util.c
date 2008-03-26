/*
 * smtp_util.c
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
 * Description:
 *
 * This file contains SMTP helper functions.
 *
 * Entry point functions:
 *
 *    safe_strchr()
 *    safe_strstr()
 *    copy_to_space()
 *    safe_sscanf()
 *
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "debug.h"

#include "snort_smtp.h"
#include "smtp_util.h"


/*
 * Search for a character within a buffer, safely
 *
 * @param   buf         buffer to search
 * @param   c           character to search for
 * @param   len         length of buffer to search
 *
 * @return  p           pointer to first character found
 * @retval  NULL        if character not found
 */
char * safe_strchr(char *buf, char c, u_int len)
{
    char *p = buf;

    while (len > 0)
    {
        if ( *p == c )
        {
            return p;
        }
        p++;
        len--;
    }

    return NULL;
}


/*
 * Copy up to a space char, or to buffer size
 *
 * @param   to      buffer to copy to
 * @param   from    buffer to copy from
 * @param   to_len  size of to buffer
 *
 * @return none
 */
void copy_to_space(char *to, char *from, int to_len)
{
    if (to == NULL || from == NULL || to_len < 1)
        return;

    while ((to_len > 1) && !isspace((int)(*from)))
    {
        *to = *from;
        to++;
        from++;
        to_len--;
    }

    *to = '\0';
}

/****************************************************************
 *
 *  Function: make_skip(char *, int)
 *
 *  Purpose: Create a Boyer-Moore skip table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the skip table
 *
 ****************************************************************/
int *make_skip(char *ptrn, int plen)
{
    int *skip = (int *) malloc(256 * sizeof(int));
    int  i;

    if (skip == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate skip for Boyer-Moore\n");
        //return NULL;
    }

    for ( i = 0; i < 256; i++ )
        skip[i] = plen + 1;

    while(plen != 0)
        skip[(unsigned char) *ptrn++] = plen--;

    return skip;
}



/****************************************************************
 *
 *  Function: make_shift(char *, int)
 *
 *  Purpose: Create a Boyer-Moore shift table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the shift table
 *
 ****************************************************************/
int *make_shift(char *ptrn, int plen)
{
    int *shift = (int *) malloc(plen * sizeof(int));
    int *sptr = shift + plen - 1;
    char *pptr = ptrn + plen - 1;
    char c;

    if (shift == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate shift for Boyer-Moore\n");
        //return NULL;
    }

    c = ptrn[plen - 1];

    *sptr = 1;

    while(sptr-- != shift)
    {
        char *p1 = ptrn + plen - 2, *p2, *p3;

        do
        {
            while(p1 >= ptrn && *p1-- != c);

            p2 = ptrn + plen - 2;
            p3 = p1;

            while(p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr);
        }
        while(p3 >= ptrn && p2 >= pptr);

        *sptr = shift + plen - sptr + p2 - p3;

        pptr--;
    }

    return shift;
}

void cleanup_boyer_moore(t_bm *bm)
{
    if (!bm)
        return;

    free(bm->shift);
    free(bm->skip);
}

int make_boyer_moore(t_bm *bm, char *ptrn, int plen)
{
    bm->ptrn = ptrn;
    bm->plen = plen;

    bm->skip = make_skip(ptrn, plen);
    if ( !bm->skip )
        return 0;
    bm->shift = make_shift(ptrn, plen);
    if ( !bm->shift )
        return 0;

    return 1;
}


/****************************************************************
 *
 *  Function: bm_search(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
char * bm_search(char *buf, int blen, t_bm *bm)
{
    int b_idx = bm->plen;

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_PATTERN_MATCH,"buf: %p  blen: %d  ptrn: %p  "
                "plen: %d\n", buf, blen, bm->ptrn, bm->plen););

    if(bm->plen == 0)
        return buf;

    while(b_idx <= blen)
    {
        int p_idx = bm->plen, skip_stride, shift_stride;

        while(buf[--b_idx] == bm->ptrn[--p_idx])
        {
            if(b_idx < 0)
                return NULL;

            if(p_idx == 0)
            {
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_PATTERN_MATCH, 
                            "Pattern matched."););

                return &buf[b_idx];

            }
        }

        skip_stride = bm->skip[(unsigned char) buf[b_idx]];
        shift_stride = bm->shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_PATTERN_MATCH,
                "Pattern did not match."););

    return NULL;
}


