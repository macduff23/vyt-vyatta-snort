/****************************************************************************
 *
 * Copyright (C) 2003-2007 Sourcefire, Inc.
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
 
/*
     sfhashfcn.c 

     Each hash table must allocate it's own SFGHASH struct, this is because
     sfghash_new uses the number of rows in the hash table to modulo the random
     values.

*/

#include "sfhashfcn.h"

/*
 *   Primiitive Prime number test, not very fast nor efficient, but should be ok for 
 *   hash table sizes of typical size.  NOT for real-time usage!
 */
static int isPrime(int num )
{
    int i;
    for(i=2;i<num;i++)
    {
        if( (num % i) == 0 ) break;//oops not prime, should have a remainder
    }
    if( i == num ) return 1;
    return 0;
}
/*
 *  Iterate number till we find a prime.
 */
static int calcNextPrime(int num )
{
    while( !isPrime( num ) ) num++;

    return num;
}

SFHASHFCN * sfhashfcn_new( int m )
{
   SFHASHFCN *p;
   unsigned   x;

   p = (SFHASHFCN*) calloc( 1,sizeof(SFHASHFCN) );
   if( !p )
       return 0;

   srand( (unsigned) time(0) );

   p->seed       = calcNextPrime( rand() % m );
   p->scale      = calcNextPrime( rand() % m );
   x = rand();
   p->hardener   = ( x * rand() ) ^ 0xe0c0b0a0;

   p->hash_fcn   = &sfhashfcn_hash;
   p->keycmp_fcn = &memcmp;
       
   return p;
}

void sfhashfcn_free( SFHASHFCN * p )
{
   if( p )
   {
       free( p);
   }
}

unsigned sfhashfcn_hash( SFHASHFCN * p, unsigned char *d, int n )
{
    unsigned hash = p->seed;
    while( n )
    {
        hash *=  p->scale;
        hash += *d++;
        n--;
    }
    return hash ^ p->hardener;
}


/** 
 * Make sfhashfcn use a separate set of operators for the backend.
 *
 * @param h sfhashfcn ptr
 * @param hash_fcn user specified hash function
 * @param keycmp_fcn user specified key comparisoin function
 */
int sfhashfcn_set_keyops( SFHASHFCN *h,
                          unsigned (*hash_fcn)( SFHASHFCN * p,
                                                unsigned char *d,
                                                int n),
                          int (*keycmp_fcn)( const void *s1,
                                             const void *s2,
                                             size_t n))
{
    if(h && hash_fcn && keycmp_fcn)
    {
        h->hash_fcn   = hash_fcn;
        h->keycmp_fcn = keycmp_fcn;

        return 0;
    }

    return -1;
}
                        
