/****************************************************************************
 *
 * Copyright (C) 2005-2009 Sourcefire, Inc.
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
 
#include "debug.h"
#include "detect.h"
#include "plugbase.h"
#include "mstring.h"
#include "sfxhash.h"
#include "util.h"
#include "decode.h"

#include "stream5_common.h"
#include "stream_api.h"
#include "snort_stream5_session.h"
#include "stream_ignore.h"

#include "plugin_enum.h"
#include "rules.h"
#include "snort.h"
#include "inline.h"

#include "portscan.h" /* To know when to create sessions for all UDP */

#include "dynamic-plugins/sp_dynamic.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats s5UdpPerfStats;
#endif

/*  M A C R O S  **************************************************/
/* actions */
#define ACTION_NOTHING                  0x00000000

/* sender/responder ip/port dereference */
#define udp_sender_ip lwSsn->client_ip
#define udp_sender_port lwSsn->client_port
#define udp_responder_ip lwSsn->server_ip
#define udp_responder_port lwSsn->server_port

/*  D A T A  S T R U C T U R E S  ***********************************/
typedef struct _UdpSession
{
    Stream5LWSession *lwSsn;

    struct timeval ssn_time;

    //u_int8_t    c_ttl;
    //u_int8_t    s_ttl;

} UdpSession;

typedef struct _Stream5UdpPolicy
{
    u_int32_t   session_timeout;
    u_int16_t   flags;
    IpAddrSet   *bound_addrs;
} Stream5UdpPolicy;

static u_int8_t udp_ports[MAX_PORTS+1];

/*  G L O B A L S  **************************************************/
static Stream5SessionCache *udp_lws_cache;
static Stream5UdpPolicy **udpPolicyList = NULL; /* List of Policies configured */
static u_int8_t numUdpPolicies = 0;
static MemPool udp_session_mempool;

/*  P R O T O T Y P E S  ********************************************/
static void Stream5ParseUdpArgs(char *, Stream5UdpPolicy *);
static void Stream5PrintUdpConfig(Stream5UdpPolicy *);
void UdpSessionCleanup(Stream5LWSession *lwssn);
static int ProcessUdp(Stream5LWSession *, Packet *, Stream5UdpPolicy *);

void Stream5InitUdp(void)
{
    /* Now UDP */ 
    if((udp_lws_cache == NULL) && s5_global_config.track_udp_sessions)
    {
        udp_lws_cache = InitLWSessionCache(s5_global_config.max_udp_sessions,
                30, 5, 0, &UdpSessionCleanup);

        if(!udp_lws_cache)
        {
            FatalError("Unable to init stream5 UDP session cache, no UDP "
                       "stream inspection!\n");
        }
        mempool_init(&udp_session_mempool, s5_global_config.max_udp_sessions, sizeof(UdpSession));
    }
}

void Stream5UdpPolicyInit(char *args)
{
    Stream5UdpPolicy *s5UdpPolicy;
    s5UdpPolicy = (Stream5UdpPolicy *) SnortAlloc(sizeof(Stream5UdpPolicy));
    s5UdpPolicy->bound_addrs = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));

    Stream5ParseUdpArgs(args, s5UdpPolicy);

    /* Now add this context to the internal list */
    if (udpPolicyList == NULL)
    {
        numUdpPolicies = 1;
        udpPolicyList = (Stream5UdpPolicy **)SnortAlloc(sizeof (Stream5UdpPolicy *)
            * numUdpPolicies);
    }
    else
    {
        Stream5UdpPolicy **tmpPolicyList =
            (Stream5UdpPolicy **)SnortAlloc(sizeof (Stream5UdpPolicy *)
            * (++numUdpPolicies));
        memcpy(tmpPolicyList, udpPolicyList,
            sizeof(Stream5UdpPolicy *) * (numUdpPolicies-1));
        free(udpPolicyList);
        
        udpPolicyList = tmpPolicyList;
    }
    udpPolicyList[numUdpPolicies-1] = s5UdpPolicy;

    Stream5PrintUdpConfig(s5UdpPolicy);

    return;
}

static void Stream5ParseUdpArgs(char *args, Stream5UdpPolicy *s5UdpPolicy)
{
    char **toks;
    int num_toks;
    int i;
    char *index;
    char **stoks = NULL;
    int s_toks;
    char *endPtr = NULL;

    s5UdpPolicy->session_timeout = S5_DEFAULT_SSN_TIMEOUT;
    s5UdpPolicy->flags = 0;

    if(args != NULL && strlen(args) != 0)
    {
        toks = mSplit(args, ",", 6, &num_toks, 0);

        i=0;

        while(i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 3, &s_toks, 0);

            if (s_toks == 0)
            {
                FatalError("%s(%d) => Missing parameter in Stream5 UDP config.\n",
                    file_name, file_line);
            }

            if(!strcasecmp(stoks[0], "timeout"))
            {
                if(stoks[1])
                {
                    s5UdpPolicy->session_timeout = strtoul(stoks[1], &endPtr, 10);
                }
                
                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid timeout in config file.  Integer parameter required.\n",
                            file_name, file_line);
                }

                if ((s5UdpPolicy->session_timeout > S5_MAX_SSN_TIMEOUT) ||
                    (s5UdpPolicy->session_timeout < S5_MIN_SSN_TIMEOUT))
                {
                    FatalError("%s(%d) => Invalid timeout in config file.  "
                        "Must be between %d and %d\n",
                        file_name, file_line,
                        S5_MIN_SSN_TIMEOUT, S5_MAX_SSN_TIMEOUT);
                }

                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream5 UDP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if (!strcasecmp(stoks[0], "ignore_any_rules"))
            {
                s5UdpPolicy->flags |= STREAM5_CONFIG_IGNORE_ANY;

                if (s_toks > 1)
                {
                    FatalError("%s(%d) => Invalid Stream5 UDP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => Invalid Stream5 UDP Policy option\n", 
                            file_name, file_line);
            }

            mSplitFree(&stoks, s_toks);
            i++;
        }

        mSplitFree(&toks, num_toks);

        if(s5UdpPolicy->bound_addrs == NULL)
        {
            /* allocate and initializes the
             * IpAddrSet at the same time
             * set to "any"
             */
            s5UdpPolicy->bound_addrs = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));
        }
    }
    return;
}

static void Stream5PrintUdpConfig(Stream5UdpPolicy *s5UdpPolicy)
{
    LogMessage("Stream5 UDP Policy config:\n");
    LogMessage("    Timeout: %d seconds\n", s5UdpPolicy->session_timeout);
    if (s5UdpPolicy->flags)
    {
        LogMessage("    Options:\n");
        if (s5UdpPolicy->flags & STREAM5_CONFIG_IGNORE_ANY)
        {
            LogMessage("        Ignore Any -> Any Rules: YES\n");
        }
    }
    //IpAddrSetPrint("    Bound Addresses:", s5UdpPolicy->bound_addrs);
}


int Stream5VerifyUdpConfig(void)
{
    if (!udp_lws_cache)
        return -1;

    if (numUdpPolicies < 1)
        return -1;

    /* Post-process UDP rules to establish UDP ports to inspect. */
    setPortFilterList(udp_ports, IPPROTO_UDP,
            (udpPolicyList[0]->flags & STREAM5_CONFIG_IGNORE_ANY));


    //printf ("UDP Ports with Inspection/Monitoring\n");
    //s5PrintPortFilter(udp_ports);
    return 0;
}

#ifdef DEBUG_STREAM5
static void PrintUdpSession(UdpSession *us)
{
    LogMessage("UdpSession:\n");
    LogMessage("    ssn_time:           %lu\n", us->ssn_time.tv_sec);
    LogMessage("    sender IP:          0x%08X\n", us->udp_sender_ip);
    LogMessage("    responder IP:          0x%08X\n", us->udp_responder_ip);
    LogMessage("    sender port:        %d\n", us->udp_sender_port);
    LogMessage("    responder port:        %d\n", us->udp_responder_port);

    LogMessage("    flags:              0x%X\n", us->lwSsn->session_flags);
}
#endif

Stream5LWSession *GetLWUdpSession(SessionKey *key)
{
    return GetLWSessionFromKey(udp_lws_cache, key);
}

void UdpSessionCleanup(Stream5LWSession *lwssn)
{
    UdpSession *udpssn = NULL;

    if (lwssn->proto_specific_data)
        udpssn = (UdpSession *)lwssn->proto_specific_data->data;

    if (!udpssn)
    {
        /* Huh? */
        return;
    }

    /* Cleanup the proto specific data */
    mempool_free(&udp_session_mempool, lwssn->proto_specific_data);
    lwssn->proto_specific_data = NULL;
    lwssn->session_state = STREAM5_STATE_NONE;
    lwssn->session_flags = SSNFLAG_NONE;
    lwssn->expire_time = 0;
    lwssn->ignore_direction = 0;

    s5stats.udp_sessions_released++;

    RemoveUDPSession(&sfPerf.sfBase);
}

void Stream5ResetUdp(void)
{
    PurgeLWSessionCache(udp_lws_cache);
    mempool_clean(&udp_session_mempool);
}

void Stream5CleanUdp(void)
{
    /* Clean up hash table -- delete all sessions */
    DeleteLWSessionCache(udp_lws_cache);
    udp_lws_cache = NULL;

    mempool_destroy(&udp_session_mempool);
}

static int NewUdpSession(Packet *p,
                         Stream5LWSession *lwssn,
                         Stream5UdpPolicy *s5UdpPolicy)
{
    UdpSession *tmp;
    MemBucket *tmpBucket;
    /******************************************************************
     * create new sessions
     *****************************************************************/
    tmpBucket = mempool_alloc(&udp_session_mempool);
    if (tmpBucket == NULL)
        return -1;

    tmp = tmpBucket->data;
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Creating new session tracker!\n"););

    tmp->ssn_time.tv_sec = p->pkth->ts.tv_sec;
    tmp->ssn_time.tv_usec = p->pkth->ts.tv_usec;
    lwssn->session_flags |= SSNFLAG_SEEN_SENDER;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "adding UdpSession to lightweight session\n"););
    lwssn->proto_specific_data = tmpBucket;
    lwssn->protocol = GET_IPH_PROTO(p);
    lwssn->direction = FROM_SENDER;
    tmp->lwSsn = lwssn;

#ifdef DEBUG_STREAM5
    PrintUdpSession(tmp);
#endif
    Stream5SetExpire(p, lwssn, s5UdpPolicy->session_timeout);

    s5stats.udp_sessions_created++;

    AddUDPSession(&sfPerf.sfBase);
    return 0;
}


/*
 * Main entry point for UDP
 */
int Stream5ProcessUdp(Packet *p)
{
    Stream5UdpPolicy *s5UdpPolicy = NULL;
    SessionKey skey;
    Stream5LWSession *lwssn = NULL;
    int policyIndex;

#ifdef SUP_IP6
// XXX-IPv6 Stream5ProcessUDP debugging
#else
    DEBUG_WRAP(
            DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE),
                "Got UDP Packet 0x%X:%d ->  0x%X:%d\n  "
                "dsize: %lu\n"
                "active sessions: %lu\n",
                p->iph->ip_src.s_addr,
                p->sp,
                p->iph->ip_dst.s_addr,
                p->dp,
                p->dsize,
                sfxhash_count(udp_lws_cache->hashTable));
            );
#endif

    /* Find an Udp policy for this packet */
    for (policyIndex = 0; policyIndex < numUdpPolicies; policyIndex++)
    {
        s5UdpPolicy = udpPolicyList[policyIndex];
        
        /*
         * Does this policy handle packets to this IP address?
         */
        if(IpAddrSetContains(s5UdpPolicy->bound_addrs, GET_DST_ADDR(p)))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "[Stream5] Found udp policy in IpAddrSet\n"););
            break;
        }
        else
        {
            s5UdpPolicy = NULL;
        }
    }

    if (!s5UdpPolicy)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "[Stream5] Could not find Udp Policy context "
                    "for IP %s\n", inet_ntoa(GET_DST_ADDR(p))););
        return 0;
    }

    if (isPacketFilterDiscard(p, s5UdpPolicy->flags & STREAM5_CONFIG_IGNORE_ANY)
            == PORT_MONITOR_PACKET_DISCARD)
    {
        //ignore the packet
        UpdateFilteredPacketStats(&sfPerf.sfBase, IPPROTO_UDP);
        return 0;
    }

    /* UDP Sessions required */
    if ((lwssn = GetLWSession(udp_lws_cache, p, &skey)) == NULL)
    {
        /* Create a new session, mark SENDER seen */
        lwssn = NewLWSession(udp_lws_cache, p, &skey);
        s5stats.total_udp_sessions++;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5: Retrieved existing session object.\n"););
    }

    if (!lwssn)
    {
        LogMessage("Stream5: Failed to retrieve session object.  Out of memory?\n");
        return -1;
    }

    p->ssnptr = lwssn;

    /*
     * Check if the session is expired.
     * Should be done before we do something with the packet...
     * ie, Insert a packet, or handle state change SYN, FIN, RST, etc.
     */
    if ((lwssn->session_state & STREAM5_STATE_TIMEDOUT) ||
        Stream5Expire(p, lwssn))
    {
        lwssn->session_flags |= SSNFLAG_TIMEDOUT;

        /* Session is timed out */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5 UDP session timedout!\n"););

        /* Clean it up */
        UdpSessionCleanup(lwssn);

        ProcessUdp(lwssn, p, s5UdpPolicy);
    }
    else
    {
        ProcessUdp(lwssn, p, s5UdpPolicy);
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Finished Stream5 UDP cleanly!\n"
                    "---------------------------------------------------\n"););
    }
    MarkupPacketFlags(p, lwssn);
    Stream5SetExpire(p, lwssn, s5UdpPolicy->session_timeout);

    return 0;
}

static int ProcessUdp(Stream5LWSession *lwssn, Packet *p,
        Stream5UdpPolicy *s5UdpPolicy)
{
    char ignore = 0;
    UdpSession *udpssn = NULL;
    DEBUG_WRAP(
            char *t = NULL;
            char *l = NULL;
            );

    if (lwssn->proto_specific_data != NULL)
        udpssn = (UdpSession *)lwssn->proto_specific_data->data;

    if (lwssn->protocol != IPPROTO_UDP)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Lightweight session not UDP on UDP packet\n"););
        return ACTION_NOTHING;
    }

    if (lwssn->session_flags & (SSNFLAG_DROP_CLIENT|SSNFLAG_DROP_SERVER))
    {
        /* figure out direction of this packet */
        GetLWPacketDirection(p, lwssn);
        /* Got a packet on a session that was dropped (by a rule). */

        /* TODO: Send reset to other side if not already done for inline mode */
        //if (!(lwssn->session_flags & SSNFLAG_SERVER_RESET)
        //{
        //    Send Server Reset
        //    lwssn->session_state |= STREAM5_STATE_SERVER_RESET;
        //}
        //if (!(lwssn->session_flags & SSNFLAG_CLIENT_RESET)
        //{
        //    Send Client Reset
        //    lwssn->session_state |= STREAM5_STATE_CLIENT_RESET;
        //}
        /* Drop this packet */
        if (((p->packet_flags & PKT_FROM_SERVER) &&
             (lwssn->session_flags & SSNFLAG_DROP_SERVER)) ||
            ((p->packet_flags & PKT_FROM_CLIENT) &&
             (lwssn->session_flags & SSNFLAG_DROP_CLIENT)))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Blocking %s packet as session was blocked\n",
                        p->packet_flags & PKT_FROM_SERVER ?
                        "server" : "client"););
            DisableDetect(p);
            /* Still want to add this number of bytes to totals */
            SetPreprocBit(p, PP_PERFMONITOR);
            InlineDrop(p);
            return ACTION_NOTHING;
        }
    }

    if (udpssn == NULL)
    {
        lwssn->direction = FROM_SENDER;
        IP_COPY_VALUE(lwssn->client_ip, GET_SRC_IP(p));
        lwssn->client_port = p->udph->uh_sport;
        IP_COPY_VALUE(lwssn->server_ip, GET_DST_IP(p));
        lwssn->server_port = p->udph->uh_dport;
        lwssn->session_state |= STREAM5_STATE_SENDER_SEEN;
        if (NewUdpSession(p, lwssn, s5UdpPolicy) == -1)
            return ACTION_NOTHING;
        udpssn = (UdpSession *)lwssn->proto_specific_data->data;
    }

    /* figure out direction of this packet */
    GetLWPacketDirection(p, lwssn);

    if (((p->packet_flags & PKT_FROM_SERVER) && (lwssn->ignore_direction & SSN_DIR_CLIENT)) ||
        ((p->packet_flags & PKT_FROM_CLIENT) && (lwssn->ignore_direction & SSN_DIR_SERVER)))
    {
        Stream5DisableInspection(lwssn, p);
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5 Ignoring packet from %d. "
                    "Session marked as ignore\n",
                    p->packet_flags & PKT_FROM_CLIENT? "sender" : "responder"););
        return ACTION_NOTHING;
    }

    /* Check if the session is to be ignored */
    ignore = CheckIgnoreChannel(p);
    if (ignore)
    {
        /* Set the directions to ignore... */
        lwssn->ignore_direction = ignore;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5: Ignoring packet from %d. "
                    "Marking session marked as ignore.\n",
                    p->packet_flags & PKT_FROM_CLIENT? "sender" : "responder"););
        Stream5DisableInspection(lwssn, p);
        return ACTION_NOTHING;
    }

    /* if both seen, mark established */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5: Updating on packet from responder\n"););
        lwssn->session_flags |= SSNFLAG_SEEN_RESPONDER;

        DEBUG_WRAP(
                t = "Responder";
                l = "Sender");
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5: Updating on packet from client\n"););
        /* if we got here we had to see the SYN already... */
        lwssn->session_flags |= SSNFLAG_SEEN_SENDER;

        DEBUG_WRAP(
                t = "Sender";
                l = "Responder");
    }

    if (!(lwssn->session_flags & SSNFLAG_ESTABLISHED))
    {
        if ((lwssn->session_flags & SSNFLAG_SEEN_SENDER) &&
            (lwssn->session_flags & SSNFLAG_SEEN_RESPONDER))
        {
            lwssn->session_flags |= SSNFLAG_ESTABLISHED;
        }
    }

    return ACTION_NOTHING;
}

void UdpUpdateDirection(Stream5LWSession *ssn, char dir,
                        snort_ip_p ip, u_int16_t port)
{
    UdpSession *udpssn = (UdpSession *)ssn->proto_specific_data->data;
    snort_ip tmpIp;
    u_int16_t tmpPort;

#ifdef SUP_IP6
    if (IP_EQUALITY(&udpssn->udp_sender_ip, ip) && (udpssn->udp_sender_port == port))
    {
        if ((dir == SSN_DIR_SENDER) && (ssn->direction == SSN_DIR_SENDER))
        {
            /* Direction already set as SENDER */
            return;
        }
    }
    else if (IP_EQUALITY(&udpssn->udp_responder_ip, ip) && (udpssn->udp_responder_port == port))
    {
        if ((dir == SSN_DIR_RESPONDER) && (ssn->direction == SSN_DIR_RESPONDER))
        {
            /* Direction already set as RESPONDER */
            return;
        }
    }
#else
    if (IP_EQUALITY(udpssn->udp_sender_ip, ip) && (udpssn->udp_sender_port == port))
    {
        if ((dir == SSN_DIR_SENDER) && (ssn->direction == SSN_DIR_SENDER))
        {
            /* Direction already set as SENDER */
            return;
        }
    }
    else if (IP_EQUALITY(udpssn->udp_responder_ip, ip) && (udpssn->udp_responder_port == port))
    {
        if ((dir == SSN_DIR_RESPONDER) && (ssn->direction == SSN_DIR_RESPONDER))
        {
            /* Direction already set as RESPONDER */
            return;
        }
    }
#endif

    /* Swap them -- leave ssn->direction the same */
    tmpIp = udpssn->udp_sender_ip;
    tmpPort = udpssn->udp_sender_port;
    udpssn->udp_sender_ip = udpssn->udp_responder_ip;
    udpssn->udp_sender_port = udpssn->udp_responder_port;
    udpssn->udp_responder_ip = tmpIp;
    udpssn->udp_responder_port = tmpPort;
}

void s5UdpSetPortFilterStatus(
        unsigned short port, 
        int status
        )
{
    udp_ports[port] |= status;
}

int s5UdpGetPortFilterStatus(
        unsigned short port 
        )
{
    return udp_ports[port];
}

