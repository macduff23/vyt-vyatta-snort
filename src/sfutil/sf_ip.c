/*
** Copyright (C) 1998-2009 Sourcefire, Inc.
** Adam Keeton
** Kevin Liu <kliu@sourcefire.com>
** 
** $Id$
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

/*
 * Adam Keeton
 * sf_ip.c
 * 11/17/06
 *
 * Library for managing IP addresses of either v6 or v4 families.  
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h> /* For ceil */
#include "sf_ip.h"

/* For inet_pton */
#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif  /* WIN32 */

#ifdef TESTER
#define FatalError printf
#endif

/* Support function .. but could see some external uses */
static INLINE int sfip_length(sfip_t *ip) {
    ARG_CHECK1(ip, 0);

    if(sfip_family(ip) == AF_INET) return 4;
    return 16;
}

/* Support function */
// note that an ip6 address may have a trailing dotted quad form
// but that it always has at least 2 ':'s; furthermore there is
// no valid ip4 format (including mask) with 2 ':'s
// we don't have to figure out if the format is entirely legal
// we just have to be able to tell correct formats apart
static INLINE int sfip_str_to_fam(const char *str) {
    const char* s;
    ARG_CHECK1(str, 0);
    s = strchr(str, (int)':');
    if ( s && strchr(s+1, (int)':') ) return AF_INET6;
    if ( strchr(str, (int)'.') ) return AF_INET;
    return AF_UNSPEC;
}

/* Place-holder allocation incase we want to do something more indepth later */
static INLINE sfip_t *_sfip_alloc() {
    /* Note: using calloc here instead of SnortAlloc since the dynamic libs 
     * can't presently resolve SnortAlloc */
    return (sfip_t*)calloc(sizeof(sfip_t), 1); 
}

/* Masks off 'val' bits from the IP contained within 'ip' */
static INLINE int sfip_cidr_mask(sfip_t *ip, int val) {
    int i;
    unsigned int mask = 0; 
    unsigned int *p;
    int index = (int)ceil(val / 32.0) - 1;
   
    ARG_CHECK1(ip, SFIP_ARG_ERR);

    p = ip->ip32;

    if( val < 0 ||
        ((sfip_family(ip) == AF_INET6) && val > 128) ||
        ((sfip_family(ip) == AF_INET) && val > 32) ) {
        return SFIP_ARG_ERR;
    }
    
    /* Build the netmask by converting "val" into 
     * the corresponding number of bits that are set */
    for(i = 0; i < 32- (val - (index * 32)); i++)
        mask = (mask<<1) + 1;

    p[index] = htonl((ntohl(p[index]) & ~mask));

    index++;

    /* 0 off the rest of the IP */
    for( ; index<4; index++) p[index] = 0;

    return SFIP_SUCCESS;
}

/* Allocate IP address from a character array describing the IP */
sfip_t *sfip_alloc(const char *ip, SFIP_RET *status) {
    int tmp;
    sfip_t *ret;
   
    if(!ip) {
        if(status)
            *status = SFIP_ARG_ERR;
        return NULL;
    }

    if((ret = _sfip_alloc()) == NULL) {
        if(status) 
            *status = SFIP_ALLOC_ERR;
        return NULL;
    }
    
    if( (tmp = sfip_pton(ip, ret)) != SFIP_SUCCESS) {
        if(status) 
            *status = tmp;

        sfip_free(ret);
        return NULL;
    }

    if(status) 
        *status = SFIP_SUCCESS;

    return ret;
}

/* Allocate IP address from an array of 8 byte integers */
sfip_t *sfip_alloc_raw(void *ip, int family, SFIP_RET *status) {
    sfip_t *ret;

    if(!ip) {
        if(status)
            *status = SFIP_ARG_ERR;
        return NULL;
    }

    if((ret = _sfip_alloc()) == NULL) {
        if(status)
            *status = SFIP_ALLOC_ERR;
        return NULL;
    }

    ret->bits = (family==AF_INET?32:128);
    ret->family = family;
    /* XXX Replace with appropriate "high speed" copy */
    memcpy(ret->ip8, ip, ret->bits/8);

    if(status)
        *status = SFIP_SUCCESS;

    return ret;
}

/* Support function for _netmask_str_to_bit_count */
static INLINE int _count_bits(unsigned int val) {
    unsigned int count; 

    for (count = 0; val; count++) {
        val &= val - 1;
    }

    return count;
}

/* Support function for sfip_pton.  Used for converting a netmask string
 * into a number of bits to mask off */
static INLINE int _netmask_str_to_bit_count(char *mask, int family) {
    u_int32_t buf[4];
    int bits, i, nBits, nBytes;
    uint8_t* bytes = (uint8_t*)buf;

    /* XXX 
     * Mask not validated.  
     * Only sfip_pton should be using this function, and using it safely. 
     * XXX */

    if(inet_pton(family, mask, buf) < 1)
        return -1;

    bits =  _count_bits(buf[0]);

    if(family == AF_INET6) {
        bits += _count_bits(buf[1]);
        bits += _count_bits(buf[2]);
        bits += _count_bits(buf[3]);
        nBytes = 16;
    } else {
        nBytes = 4;
    }

    // now make sure that only the most significant bits are set
    nBits = bits;
    for ( i = 0; i < nBytes; i++ ) {
        if ( nBits >= 8 ) {
            if ( bytes[i] != 0xff ) return -1;
            nBits -= 8;

        } else if ( nBits == 0 ) {
            if ( bytes[i] != 0x00 ) return -1;

        } else {
            if ( bytes[i] != ((0xff00 >> nBits) & 0xff) ) return -1;
            nBits = 0;
        }
    }
    return bits;
}

/* Parses "src" and stores results in "dst" */
SFIP_RET sfip_pton(const char *src, sfip_t *dst) {
    char *mask;
    char *sfip_buf;
    char *ip;
    int bits;

    if(!dst || !src) 
        return SFIP_ARG_ERR;
            
    if((sfip_buf = strdup(src)) == NULL) 
        return SFIP_ALLOC_ERR;

    ip = sfip_buf;
    dst->family = sfip_str_to_fam(src);

    /* skip whitespace or opening bracket */
    while(isspace((int)*ip) || (*ip == '[')) ip++;

    /* check for and extract a mask in CIDR form */
    if( (mask = strchr(ip, (int)'/')) != NULL ) {
        /* NULL out this character so inet_pton will see the 
         * correct ending to the IP string */
        char* end = mask++;
        while ( (end > ip) && isspace((int)end[-1]) ) end--;
        *end = 0;

        while(isspace((int)*mask)) mask++;

        /* verify a leading digit */
        if(((dst->family == AF_INET6) && !isxdigit((int)*mask)) ||
           ((dst->family == AF_INET) && !isdigit((int)*mask))) {
            free(sfip_buf);                          
            return SFIP_CIDR_ERR;
        }

        /* Check if there's a netmask here instead of the number of bits */
        if(strchr(mask, (int)'.') || strchr(mask, (int)':')) 
            bits = _netmask_str_to_bit_count(mask, sfip_str_to_fam(mask));
        else
            bits = atoi(mask);
    }
    else if(
            /* If this is IPv4, ia ':' may used specified to indicate a netmask */
            ((dst->family == AF_INET) && (mask = strchr(ip, (int)':')) != NULL) ||

            /* We've already skipped the leading whitespace, if there is more 
             * whitespace, then there's probably a netmask specified after it. */
             (mask = strchr(ip, (int)' ')) != NULL
    ) {
        char* end = mask++;
        while ( (end > ip) && isspace((int)end[-1]) ) end--;
        *end = 0;  /* Now the IP will end at this point */

        /* skip whitespace */
        while(isspace((int)*mask)) mask++;

        /* Make sure we're either looking at a valid digit, or a leading
         * colon, such as can be the case with IPv6 */
        if(((dst->family == AF_INET) && isdigit((int)*mask)) ||
           ((dst->family == AF_INET6) && (isxdigit((int)*mask) || *mask == ':'))) { 
            bits = _netmask_str_to_bit_count(mask, sfip_str_to_fam(mask));
        } 
        /* No netmask */
        else { 
            if(dst->family == AF_INET) bits = 32;
            else bits = 128;        
        }
    }
    /* No netmask */
    else {
        if(dst->family == AF_INET) bits = 32;
        else bits = 128;        
    }

    if(inet_pton(dst->family, ip, dst->ip8) < 1) {
        free(sfip_buf);                          
        return SFIP_INET_PARSE_ERR;
    }

    /* Store mask */
    dst->bits = bits;

    /* Apply mask */
    if(sfip_cidr_mask(dst, bits) != SFIP_SUCCESS) {
        free(sfip_buf);
        return SFIP_INVALID_MASK;
    }
    
    free(sfip_buf);
    return SFIP_SUCCESS;
}

/* Sets existing IP, "dst", to be source IP, "src" */
SFIP_RET sfip_set_raw(sfip_t *dst, void *src, int family) {
    
    ARG_CHECK3(dst, src, dst->ip32, SFIP_ARG_ERR);

    dst->family = family;

    if(family == AF_INET) {
        dst->ip32[0] = *(u_int32_t*)src;
        memset(&dst->ip32[1], 0, 12);
        dst->bits = 32;
    } else if(family == AF_INET6) {
        memcpy(dst->ip8, src, 16);
        dst->bits = 128;
    } else {
        return SFIP_ARG_ERR;
    }
    
    return SFIP_SUCCESS;
}

/* Sets existing IP, "dst", to be source IP, "src" */
SFIP_RET sfip_set_ip(sfip_t *dst, sfip_t *src) {
    ARG_CHECK2(dst, src, SFIP_ARG_ERR);

    dst->family = src->family;
    dst->bits = src->bits;
    dst->ip32[0] = src->ip32[0];
    dst->ip32[1] = src->ip32[1];
    dst->ip32[2] = src->ip32[2];
    dst->ip32[3] = src->ip32[3];

    return SFIP_SUCCESS;
}

/* Obfuscates an IP
 * Makes 'ip': ob | (ip & mask) */
void sfip_obfuscate(sfip_t *ob, sfip_t *ip) {
    unsigned int *ob_p, *ip_p;
    int index, i;
    unsigned int mask = 0;

    if(!ob || !ip)
        return;

    ob_p = ob->ip32;
    ip_p = ip->ip32;

    /* Build the netmask by converting "val" into 
     * the corresponding number of bits that are set */
    index = (int)ceil(ob->bits / 32.0) - 1;

    for(i = 0; i < 32- (ob->bits - (index * 32)); i++)
        mask = (mask<<1) + 1;

    /* Note: The old-Snort obfuscation code uses !mask for masking.
     * hence, this code uses the same algorithm as sfip_cidr_mask
     * except the mask below is not negated. */
    ip_p[index] = htonl((ntohl(ip_p[index]) & mask));

    index++;

    /* 0 off the rest of the IP */
    for( ; index<4; index++) ip_p[index] = 0;

    /* OR remaining pieces */
    ip_p[0] |= ob_p[0];
    ip_p[1] |= ob_p[1];
    ip_p[2] |= ob_p[2];
    ip_p[3] |= ob_p[3];
}


/* Check if ip is contained within the network specified by net */ 
/* Returns SFIP_EQUAL if so.  
 * XXX sfip_contains assumes that "ip" is 
 *      not less-specific than "net" XXX
*/
SFIP_RET sfip_contains(sfip_t *net, sfip_t *ip) {
    unsigned int bits, mask, temp, i;
    int net_fam, ip_fam;
    unsigned int *p1, *p2;

    /* SFIP_CONTAINS is returned here due to how IpAddrSetContains 
     * handles zero'ed IPs" */
    ARG_CHECK2(net, ip, SFIP_CONTAINS);

    bits = sfip_bits(net);
    net_fam = sfip_family(net);
    ip_fam = sfip_family(ip);

    /* If the families are mismatched, check if we're really comparing
     * an IPv4 with a mapped IPv4 (in IPv6) address. */
    if(net_fam != ip_fam) {
        if((net_fam != AF_INET) || !sfip_ismapped(ip))
            return SFIP_ARG_ERR;

        /* Both are really IPv4.  Only compare last 4 bytes of 'ip'*/
        p1 = net->ip32;
        p2 = &ip->ip32[3];
        
        /* Mask off bits */
        bits = 32 - bits;
        temp = (ntohl(*p2) >> bits) << bits;

        if(ntohl(*p1) == temp) return SFIP_CONTAINS;

        return SFIP_NOT_CONTAINS;
    }

    p1 = net->ip32;
    p2 = ip->ip32;

    /* Iterate over each 32 bit segment */
    for(i=0; i < bits/32 && i < 3; i++, p1++, p2++) {
        if(*p1 != *p2) 
            return SFIP_NOT_CONTAINS;
    }

    mask = 32 - (bits - 32*i);
    if ( mask == 32 ) return SFIP_CONTAINS;

    /* At this point, there are some number of remaining bits to check.
     * Mask the bits we don't care about off of "ip" so we can compare
     * the ints directly */
    temp = ntohl(*p2);
    temp = (temp >> mask) << mask;

    /* If p1 was setup correctly through this library, there is no need to 
     * mask off any bits of its own. */
    if(ntohl(*p1) == temp) 
        return SFIP_CONTAINS;

    return SFIP_NOT_CONTAINS;

}

void sfip_raw_ntop(int family, const void *ip_raw, char *buf, int bufsize) {
    int i;

    if(!ip_raw || !buf || !bufsize || 
       (family != AF_INET && family != AF_INET6) || 
       /* Make sure if it's IPv6 that the buf is large enough. */
       /* Need atleast a max of 8 fields of 4 bytes plus 7 for colons in 
        * between.  Need 1 more byte for null. */
       (family == AF_INET6 && bufsize < 8*4 + 7 + 1) ||
       /* Make sure if it's IPv4 that the buf is large enough. */
       /* 4 fields of 3 numbers, plus 3 dots and a null byte */
       (family == AF_INET && bufsize < 3*4 + 4) )
    {
        if(buf && bufsize > 0) buf[0] = 0;
        return;
    }

    /* 4 fields of at most 3 characters each */
    if(family == AF_INET) {
        u_int8_t *p = (u_int8_t*)ip_raw;

        for(i=0; p < ((u_int8_t*)ip_raw) + 4; p++) {
            i += sprintf(&buf[i], "%d", *p);

            /* If this is the last iteration, this could technically cause one
             *  extra byte to be written past the end. */
            if(i < bufsize && ((p + 1) < ((u_int8_t*)ip_raw+4)))
                buf[i] = '.';

            i++;
        }

    /* Check if this is really just an IPv4 address represented as 6, 
     * in compatible format */
#if 0
    } 
    else if(!field[0] && !field[1] && !field[2]) {
        unsigned char *p = (unsigned char *)(&ip->ip[12]);

        for(i=0; p < &ip->ip[16]; p++) 
             i += sprintf(&buf[i], "%d.", *p);
#endif
    } 
    else {
        u_int16_t *p = (u_int16_t*)ip_raw;

        for(i=0; p < ((u_int16_t*)ip_raw) + 8; p++) {
            i += sprintf(&buf[i], "%04x", ntohs(*p));

            /* If this is the last iteration, this could technically cause one
             *  extra byte to be written past the end. */
            if(i < bufsize && ((p + 1) < ((u_int16_t*)ip_raw) + 8))
                buf[i] = ':';

            i++;
        }
    }
}

/* Uses a static buffer to return a string representation of the IP */
char *sfip_to_str(const sfip_t *ip) {
    /* IPv6 addresses will be at most 8 fields, of 4 characters each, 
     * with 7 colons inbetween, one NULL, and one fudge byte for sloppy use
     * in sfip_to_strbuf */
    static char buf[8*4 + 7 + 1 + 1];

    if(!ip)
         return NULL;

    sfip_raw_ntop(sfip_family(ip), ip->ip32, buf, sizeof(buf));
    
    return buf;
}

void sfip_free(sfip_t *ip) {
    if(ip) free(ip);
}

/* Returns 1 if the IP is non-zero. 0 otherwise */
int sfip_is_loopback(sfip_t *ip) {
    unsigned int *p;

    ARG_CHECK1(ip, 0);

    if(sfip_family(ip) == AF_INET) {
        // 127.0.0.0/8 is IPv4 loopback
        return (ip->ip8[0] == 0x7f);
    }

    p = ip->ip32;

    /* Check the first 64 bits in an IPv6 address, and */
    /* verify they're zero.  If not, it's not a loopback */
    if(p[0] || p[1]) return 0;

    /* Check if the 3rd 32-bit int is zero */
    if ( p[2] == 0 ) {
        /* ::7f00:0/104 is ipv4 compatible ipv6 */
        /* ::1 is the IPv6 loopback */
        return ( (ip->ip8[12] == 0x7f) || (ntohl(p[3]) == 0x1) );
    }
    /* Check the 3rd 32-bit int for a mapped IPv4 address */
    if ( ntohl(p[2]) == 0xffff ) {
        /* ::ffff:127.0.0.0/104 is IPv4 loopback mapped over IPv6 */
        return ( ip->ip8[12] == 0x7f );
    }
    return 0;
}

int sfip_ismapped(sfip_t *ip) {
    unsigned int *p;

    ARG_CHECK1(ip, 0);

    if(sfip_family(ip) == AF_INET) 
        return 0;
       
    p = ip->ip32;

    if(p[0] || p[1] || (ntohl(p[2]) != 0xffff && p[2] != 0)) return 0;

    return 1;
}

#ifndef strndup 
char *strndup(const char *s, size_t n) {
    char *ret; 
    size_t len = strlen(s);

    if(len < n) {
        n = len;
    }
 
    ret = (char*)malloc(n+1);

    if(!ret) 
        return NULL;

    strncpy(ret, s, n);
    ret[n] = 0;
    return ret;
}
#endif


#ifdef TESTER
#define PASS 1
#define FAIL 0

static int sf_ip_failures = 0;

typedef struct {
    const char* input;
    const char* expected;
} ParseTest;

static ParseTest ptests[] = {
    { "", "255.255.255.255" },
    { "192.168.0.1", "192.168.0.1" },
    { "255.255.255.255/21", "255.255.248.0" },
    { "1.1.255.255      255.255.248.0", "1.1.248.0" },
    { " 2001:0db8:0000:0000:0000:0000:1428:57ab   ", "2001:0db8:0000:0000:0000:0000:1428:57ab" },
    { "ffff:ffff::1", "ffff:ffff:0000:0000:0000:0000:0000:0001" },
    { "fFfF::FfFf:FFFF/127", "ffff:0000:0000:0000:0000:0000:ffff:fffe" },
    { "ffff::ffff:1/8", "ff00:0000:0000:0000:0000:0000:0000:0000" },
    { "6543:21ff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ff00::", "6543:2100:0000:0000:0000:0000:0000:0000" },
    { "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32", "ffee:ddcc:0000:0000:0000:0000:0000:0000" },
    { "ffee:ddcc:bbaa:9988:7766:5544:3322:1100", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100" }, 
    { "1.2.3.4:255.0.0.0", "1.0.0.0" },
    { "1.2.3.4/255.0.0.0", "1.0.0.0" },
    { "1.2.3.4 : 255.0.0.0", "1.0.0.0" },
    { "1.2.3.4 / 255.0.0.0", "1.0.0.0" },
    { "1.2.3.4  :255.0.0.0", "1.0.0.0" },
    { "1.2.3.4/  255.0.0.0", "1.0.0.0" },
    { "1.2.3.4/16", "1.2.0.0" },
    { "1.2.3.4/ 16", "1.2.0.0" },
    { "1.2.3.4 / 16", "1.2.0.0" },
    { " 1.2.3.4 / 16 ", "1.2.0.0" },
    { "1234::1.2.3.4", "1234:0000:0000:0000:0000:0000:0102:0304" },
    { "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", "fedc:ba98:7654:3210:fedc:ba98:7654:3210" },
    { "1080:0:0:0:8:800:200C:4171", "1080:0000:0000:0000:0008:0800:200c:4171" },
    { "3ffe:2a00:100:7031::1", "3ffe:2a00:0100:7031:0000:0000:0000:0001" },
    { "1080::8:800:200C:417A", "1080:0000:0000:0000:0008:0800:200c:417a" },
    { "::192.9.5.5", "0000:0000:0000:0000:0000:0000:c009:0505" },
    { "::FFFF:129.144.52.38", "0000:0000:0000:0000:0000:ffff:8190:3426" },
    { "2010:836B:4179::836B:4179", "2010:836b:4179:0000:0000:0000:836b:4179" },
    { "::", "0000:0000:0000:0000:0000:0000:0000:0000" },
    { NULL, NULL }
};

typedef struct {
    const char* func;
    const char* arg1;
    const char* arg2;
    int expected;
} FuncTest;

// we invert expected bools to match codes[]
static FuncTest ftests[] = {
    { "sfip_is_set", "8::", NULL, 0 },
    { "sfip_is_set", "::1", NULL, 0 },
    { "sfip_is_set", "::", NULL, 1 },

    { "sfip_is_loopback", "127.0.0.0", NULL, 0 },
    { "sfip_is_loopback", "127.255.255.255", NULL, 0 },
    { "sfip_is_loopback", "128.0.0.0", NULL, 1 },
    { "sfip_is_loopback", "::1", NULL, 0 },
    { "sfip_is_loopback", "::2", NULL, 1 },
    { "sfip_is_loopback", "::7f00:0/104", NULL, 0 },
    { "sfip_is_loopback", "::ffff:127.0.0.0/104", NULL, 0 },
    { "sfip_is_loopback", "::127.0.0.0", NULL, 0 },
    { "sfip_is_loopback", "::128.0.0.1", NULL, 1 },
    { "sfip_is_loopback", "::ffff:0.0.0.1", NULL, 1 },

    { "sfip_ismapped", "::ffff:c000:280", NULL, 0 },
    { "sfip_ismapped", "8::ffff:c000:280", NULL, 1 },
    { "sfip_ismapped", "::fffe:c000:280", NULL, 1 },

    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_EQUAL },
    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:1:3:4:5:6:7:8", SFIP_GREATER },
    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:2:4:4:5:6:7:8", SFIP_LESSER },
    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:2:3:4:5:5:7:8", SFIP_GREATER },
    { "_ip6_cmp", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:8:8", SFIP_LESSER },

    { "sfip_compare", "1.2.3.4", "1.2.3.4", SFIP_EQUAL },
    { "sfip_compare", "255.255.255.255", "192.168.0.1", SFIP_GREATER },
    { "sfip_compare", "192.168.0.1", "255.255.255.255/21", SFIP_LESSER },
    { "sfip_compare", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_EQUAL },
    { "sfip_compare", "ffff:ffff::1",
      "6543:21ff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ff00::", SFIP_GREATER },
    { "sfip_compare", "1.2.3.4", "0.0.0.0", SFIP_EQUAL },
    { "sfip_compare", "1:2:3:4:5:6:7:8", "::", SFIP_EQUAL },

    { "sfip_compare_unset", "1.2.3.4", "1.2.3.4", SFIP_EQUAL },
    { "sfip_compare_unset", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", SFIP_EQUAL },
    { "sfip_compare_unset", "1.2.3.4", "0.0.0.0", SFIP_FAILURE },
    { "sfip_compare_unset", "1:2:3:4:5:6:7:8", "::", SFIP_FAILURE },

    { "sfip_fast_lt4", "1.2.3.4", "1.2.3.4", 1 },
    { "sfip_fast_lt4", "1.2.3.4", "1.2.3.5", 0 },
    { "sfip_fast_lt4", "1.2.3.5", "1.2.3.4", 1 },

    { "sfip_fast_gt4", "1.2.3.4", "1.2.3.4", 1 },
    { "sfip_fast_gt4", "1.2.3.4", "1.2.3.5", 1 },
    { "sfip_fast_gt4", "1.2.3.5", "1.2.3.4", 0 },

    { "sfip_fast_eq4", "1.2.3.4", "1.2.3.4", 0 },
    { "sfip_fast_eq4", "1.2.3.4", "1.2.3.5", 1 },
    { "sfip_fast_eq4", "1.2.3.5", "1.2.3.4", 1 },

    { "sfip_fast_lt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", 1 },
    { "sfip_fast_lt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", 0 },
    { "sfip_fast_lt6", "1:2:3:4:5:6:7:9", "1:2:3:4:5:6:7:8", 1 },

    { "sfip_fast_gt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", 1 },
    { "sfip_fast_gt6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", 1 },
    { "sfip_fast_gt6", "1:2:3:4:5:6:7:9", "1:2:3:4:5:6:7:8", 0 },

    { "sfip_fast_eq6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8", 0 },
    { "sfip_fast_eq6", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:9", 1 },
    { "sfip_fast_eq6", "1:2:3:4:5:6:7:9", "1:2:3:4:5:6:7:8", 1 },

    { "sfip_fast_cont4", "255.255.255.255", "192.168.0.1", 1 },
    { "sfip_fast_cont4", "192.168.0.1", "255.255.255.255/21", 1 },
    { "sfip_fast_cont4", "255.255.255.255/21", "255.255.255.255", 0 },
    { "sfip_fast_cont4", "255.255.255.255", "255.255.255.255/21", 1 },

    { "sfip_contains", "255.255.255.255", "192.168.0.1", SFIP_NOT_CONTAINS },
    { "sfip_contains", "192.168.0.1", "255.255.255.255/21", SFIP_NOT_CONTAINS },
    { "sfip_contains", "255.255.255.255/21", "255.255.255.255", SFIP_CONTAINS },
    { "sfip_contains", "255.255.255.255", "255.255.255.255/21", SFIP_NOT_CONTAINS },

    { "sfip_fast_cont6", "ffff:ffff::1", "ffff::ffff:1/8", 1 },
    { "sfip_fast_cont6", "ffff::ffff:1/8", "ffff:ffff::1", 0 },
    { "sfip_fast_cont6", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32",
                         "ffee:ddcc:bbaa:9988:7766:5544:3322:1100", 0 },
    { "sfip_fast_cont6", "1001:db8:85a3::/28", "1001:db0::", 0 },
    { "sfip_fast_cont6", "1001:db8:85a3::/29", "1001:db0::", 1 },

    { "sfip_contains", "ffff:ffff::1", "ffff::ffff:1/8", SFIP_NOT_CONTAINS },
    { "sfip_contains", "ffff::ffff:1/8", "ffff:ffff::1", SFIP_CONTAINS },
    { "sfip_contains", "ffee:ddcc:bbaa:9988:7766:5544:3322:1100/32",
                       "ffee:ddcc:bbaa:9988:7766:5544:3322:1100", SFIP_CONTAINS },
    { "sfip_contains", "1001:db8:85a3::/28", "1001:db0::", SFIP_CONTAINS },
    { "sfip_contains", "1001:db8:85a3::/29", "1001:db0::", SFIP_NOT_CONTAINS },

    { "sfip_contains", "255.255.255.255", 
      "2001:0db8:0000:0000:0000:0000:1428:57ab", SFIP_ARG_ERR },
    { NULL }
};

static const char* codes[] = {
    "success", 
    "failure", 
    "lesser", 
    "greater", 
    "equal", 
    "arg_err", 
    "cidr_err", 
    "inet_parse_err", 
    "invalid_mask", 
    "alloc_err", 
    "contains", 
    "not_contains", 
    "duplicate", 
    "lookup_failure", 
    "unmatched_bracket", 
    "not_any", 
    "conflict" 
};

static void FuncCheck (FuncTest* f, int result) {
    const char* status = "Passed";
    const char* code = result < sizeof(codes)/sizeof(code[0]) ? 
        codes[result] : "uh oh";

    if ( result != f->expected ) {
        status = "Failed";
        sf_ip_failures++;
    }
    if ( f->arg2 )
        printf("%s: %s(%s, %s) = %s\n",
            status, f->func, f->arg1, f->arg2, code);
    else
        printf("%s: %s(%s) = %s\n",
            status, f->func, f->arg1, code);
}

static void RunFuncs (void) {
    FuncTest* f = ftests;

    while ( f->func ) {
        sfip_t ip1, ip2;
        int result = -1;

        if ( f->arg1 ) sfip_pton(f->arg1, &ip1);
        if ( f->arg2 ) sfip_pton(f->arg2, &ip2);

        if ( !strcmp(f->func, "sfip_contains") ) {
            result = sfip_contains(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_is_set") ) {
            result = !sfip_is_set(&ip1);

        } else if ( !strcmp(f->func, "sfip_is_loopback") ) {
            result = !sfip_is_loopback(&ip1);

        } else if ( !strcmp(f->func, "sfip_ismapped") ) {
            result = !sfip_ismapped(&ip1);

        } else if ( !strcmp(f->func, "_ip6_cmp") ) {
            result = _ip6_cmp(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_compare") ) {
            result = sfip_compare(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_compare_unset") ) {
            result = sfip_compare_unset(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_fast_lt4") ) {
            result = !sfip_fast_lt4(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_fast_gt4") ) {
            result = !sfip_fast_gt4(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_fast_eq4") ) {
            result = !sfip_fast_eq4(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_fast_lt6") ) {
            result = !sfip_fast_lt6(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_fast_gt6") ) {
            result = !sfip_fast_gt6(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_fast_eq6") ) {
            result = !sfip_fast_eq6(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_fast_cont4") ) {
            result = !sfip_fast_cont4(&ip1, &ip2);

        } else if ( !strcmp(f->func, "sfip_fast_cont6") ) {
            result = !sfip_fast_cont6(&ip1, &ip2);
        }
        FuncCheck(f, result);
        f++;
    }
}

/* By using a macro, __LINE__  will be right */
#define test(msg, result) { \
    if(result == FAIL) { \
        printf("\tFAILED:\t%s\tline %d\n", msg, __LINE__); \
        sf_ip_failures++; \
    } else { \
        printf("\tPassed:\t%s\n", msg); \
    } \
}

static int test_str(const sfip_t *ip, const char *str) {
    char *s = sfip_to_str(ip);
    if(!strcmp( s, str) ) return PASS;

    printf("\tShould have seen: \"%s\"\n", str);
    printf("\tInstead saw:      \"%s\"\n\t", s);
    return FAIL;
}

int sf_ip_unittest() {
    unsigned int i = 0xffffffff;
    const int N = sizeof(ptests)/sizeof(ptests[0]) - 1;
    sfip_t *ip[N];
#if 0
    sfip_t conv;
#endif
    SFIP_RET status;
   
    /* Verify the simplest allocation method */
    puts("*********************************************************************");
    puts("Testing raw allocation:");
    ip[0] = sfip_alloc_raw(&i, AF_INET, &status);
    test("255.255.255.255", test_str(ip[0], "255.255.255.255"));

    /* The following lines verify parsing via sfip_alloc */
    /* sfip_alloc should be able to recognize IPv4 and IPv6 addresses, 
     * and extract and apply netmasks.  IPv6 address can be specified in 
     * any valid IPv6 notation as recognized by inet_pton.  Netmasks can 
     * either be specified in IP form or by using CIDR notation */
    puts("");
    puts("*********************************************************************");
    puts("Testing parsing:");
    for ( i = 1; i < N; i++ ) {
        ip[i] = sfip_alloc(ptests[i].input, &status);
        test(ptests[i].input, test_str(ip[i], ptests[i].expected));
    }

    /* Free everything and reallocate it. */
    /* This will atleast /imply/ memory is being handled somewhat properly. */
    puts("");
    puts("*********************************************************************");
    puts("Verifying deletes:");
    /* Make sure we can free: */
    for( i = 0; i < N; i++ ) sfip_free(ip[i]);

    /* Reallocate */
    i = 0xffffffff;
    ip[0] = sfip_alloc_raw(&i, AF_INET, &status);
    for( i = 1; i < N; i++ ) ip[i] = sfip_alloc(ptests[i].input, &status);
    printf("\tPassed (as best I can tell, since there was no seg fault)\n");

#if 0
    // APPARENTLY THIS CODE IS OUT OF DATE
    /* The following lines verify that IPs can be converted to different families. */
    puts("");
    puts("*********************************************************************");
    puts("Verifying IPv4<->IPv6 conversions:");
    conv = sfip_4to6(ip[0]);
    test("ipv4 -> ipv6", test_str(&conv, "0000:0000:0000:0000:0000:ffff:ffff:ffff"));
    conv = sfip_6to4(&conv);
    /* Converting an IP from v4 to v6 and back to v4 should yield the same IP. */
    test("ipv6 -> ipv4", test_str(&conv, "255.255.255.255"));
    conv = sfip_6to4(ip[4]);
    test("ipv6 -> ipv4", test_str(&conv, "20.40.87.171"));
#endif
    
    puts("");
    puts("*********************************************************************");
    puts("Testing functions:");
    RunFuncs();

    puts("");
    puts("*********************************************************************");
    puts(" ... Cleaning up");
    for(i=0; i<9; i++) { sfip_free(ip[i]); }

    printf("\n\tTotal failures: %d\n\n", sf_ip_failures);

    return sf_ip_failures;
}

//-------------------------------------
// build with:
// gcc -g -DTESTER -o sfipt -lm sf_ip.c
// then run:
// ./sfipt
//-------------------------------------

int main (int argc, char* argv[]) {
    return sf_ip_unittest();
}

#endif
