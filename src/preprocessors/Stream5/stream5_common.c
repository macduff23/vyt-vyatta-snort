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
#include "decode.h"
#include "log.h"
#include "util.h"
#include "generators.h"
#include "event_queue.h"
#include "snort.h"
#include "sf_types.h"

#include "snort_stream5_session.h"
#include "stream5_common.h"
//#include "sp_dynamic.h"
#include "portscan.h"
#include "sftarget_protocol_reference.h"
#include "sp_dynamic.h" 

static void printIgnoredRules(
        IgnoredRuleList *pIgnoredRuleList,
        int any_any_flow
        );
static void addRuleToIgnoreList(
        IgnoredRuleList **ppIgnoredRuleList, 
        OptTreeNode *otn);

/*  M A C R O S  **************************************************/
INLINE UINT64 CalcJiffies(Packet *p)
{
    UINT64 ret = 0;
    UINT64 sec = (p->pkth->ts.tv_sec * TCP_HZ);
    UINT64 usec = (p->pkth->ts.tv_usec / (1000000UL/TCP_HZ));

    ret = sec + usec;

    return ret;
    //return (p->pkth->ts.tv_sec * TCP_HZ) + 
    //       (p->pkth->ts.tv_usec / (1000000UL/TCP_HZ));
}

int Stream5Expire(Packet *p, Stream5LWSession *lwssn)
{
    UINT64 pkttime = CalcJiffies(p);

    if (lwssn->expire_time == 0)
    {
        /* Not yet set, not expired */
        return 0;
    }
    
    if((int)(pkttime - lwssn->expire_time) > 0)
    {
        sfPerf.sfBase.iStreamTimeouts++;
        lwssn->session_flags |= SSNFLAG_TIMEDOUT;
        lwssn->session_state |= STREAM5_STATE_TIMEDOUT;

        switch (lwssn->protocol)
        {
            case IPPROTO_TCP:
                s5stats.tcp_timeouts++;
                //DeleteLWSession(tcp_lws_cache, lwssn);
                break;
            case IPPROTO_UDP:
                s5stats.udp_timeouts++;
                //DeleteLWSession(udp_lws_cache, lwssn);
                break;
            case IPPROTO_ICMP:
                s5stats.icmp_timeouts++;
                //DeleteLWSession(icmp_lws_cache, lwssn);
                break;
        }
        return 1;
    }

    return 0;
}

void Stream5SetExpire(Packet *p, 
        Stream5LWSession *lwssn, u_int32_t timeout)
{
    lwssn->expire_time = CalcJiffies(p) + (timeout * TCP_HZ);
    return;
}

void MarkupPacketFlags(Packet *p, Stream5LWSession *lwssn)
{
    if(!lwssn)
        return;

    if((lwssn->session_flags & SSNFLAG_ESTABLISHED) != SSNFLAG_ESTABLISHED)
    {
        if((lwssn->session_flags & (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT)) ==
            (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT))
        {
            p->packet_flags |= PKT_STREAM_UNEST_BI;
        }
        else
        {
            p->packet_flags |= PKT_STREAM_UNEST_UNI;
        }
    }
    else
    {
        p->packet_flags |= PKT_STREAM_EST;
        if(p->packet_flags & PKT_STREAM_UNEST_UNI)
        {
            p->packet_flags ^= PKT_STREAM_UNEST_UNI;
        }
    }
}

/** Get rule list for a specific protocol
 *
 * @param rule  
 * @param ptocool protocol type 
 * @returns RuleTreeNode* rule list for specific protocol
 */
inline RuleTreeNode * protocolRuleList(RuleListNode *rule, int protocol)
{
    switch (protocol)
    {
        case IPPROTO_TCP:
            return rule->RuleList->TcpList;
        case IPPROTO_UDP:
            return rule->RuleList->UdpList;
        case IPPROTO_ICMP:
            break;
        default:
            break;
    }
    return NULL;
}

static inline char * getProtocolName (int protocol)
{
    static char *protocolName[] = {"TCP", "UDP", "ICMP"};
    switch (protocol)
    {
        case IPPROTO_TCP:
            return protocolName[0];
        case IPPROTO_UDP:
            return protocolName[1];
        case IPPROTO_ICMP:
            return protocolName[2];
            break;
        default:
            break;
    }
    return NULL;
}

/**check whether a flow bit is set for an option node.
 *
 * @param otn Option Tree Node
 * @returns 0 - no flow bit is set, 1 otherwise
 */
int Stream5OtnHasFlowOrFlowbit(OptTreeNode *otn)
{
    if (otn->ds_list[PLUGIN_CLIENTSERVER] ||
#ifdef DYNAMIC_PLUGIN
        DynamicHasFlow(otn) ||
        DynamicHasFlowbit(otn) ||
#endif
        otn->ds_list[PLUGIN_FLOWBIT])
    {
        return 1;
    }
    return 0;
}

/**initialize given port list from the given ruleset.
 * @param portList pointer to array of MAX_PORTS+1 u_int8_t. This array content 
 * is changed by walking through the rulesets.
 * @param protocol - protocol type
 */
void setPortFilterList(
        u_int8_t *portList, 
        int protocol,
        int ignoreAnyAnyRules
        )
{
#ifdef PORTLISTS
    char *port_array = NULL;
    int num_ports = 0;
    int i;
#else
    int16_t sport, dport;
#endif
    RuleListNode *rule;
    RuleTreeNode *rtn;
    OptTreeNode *otn;
    extern RuleListNode *RuleLists;
    int inspectSrc, inspectDst;
    char any_any_flow = 0;
    RuleTreeNode *pProtocolRuleList;
    IgnoredRuleList *pIgnoredRuleList = NULL;     ///list of ignored rules
    char *protocolName;

    if ((protocol == IPPROTO_TCP) && (ignoreAnyAnyRules == 0))
    {
        int j;
        for (j=0; j<MAX_PORTS; j++)
        {
            portList[j] |= PORT_MONITOR_SESSION | PORT_MONITOR_INSPECT;
        }
        return;
    }

    protocolName = getProtocolName(protocol);

    /* Post-process TCP rules to establish TCP ports to inspect. */
    for (rule=RuleLists; rule; rule=rule->next)
    {
        if(!rule->RuleList)
            continue;

        /*
        **  Get TCP rules
        */
        pProtocolRuleList = protocolRuleList(rule, protocol);
        if(pProtocolRuleList)
        {
            for(rtn = pProtocolRuleList; rtn != NULL; rtn = rtn->right)
            {
                inspectSrc = inspectDst = 0;
#ifdef PORTLISTS
                if (PortObjectHasAny(rtn->src_portobject))
                {
                    inspectSrc = -1;
                }
                else
                {
                    port_array = PortObjectCharPortArray(port_array, rtn->src_portobject, &num_ports);
                    if (port_array && num_ports != 0)
                    {
                        inspectSrc = 1;
                        for (i=0;i<SFPO_MAX_PORTS;i++)
                        {
                            if (port_array[i])
                            {
                                portList[i] |= PORT_MONITOR_INSPECT;
                                /* port specific rule */
                                for (otn = rtn->down; otn; otn = otn->next)
                                {
                                    /* Look for an OTN with flow or flowbits keyword */
                                    if (Stream5OtnHasFlowOrFlowbit(otn))
                                    {
                                        portList[i] |= PORT_MONITOR_SESSION;
                                    }
                                }
                            }
                        }
                    }
                }
                free(port_array);
                port_array = NULL;
                if (PortObjectHasAny(rtn->dst_portobject))
                {
                    inspectDst = -1;
                }
                else
                {
                    port_array = PortObjectCharPortArray(port_array, rtn->dst_portobject, &num_ports);
                    if (port_array && num_ports != 0)
                    {
                        inspectDst = 1;
                        for (i=0;i<SFPO_MAX_PORTS;i++)
                        {
                            if (port_array[i])
                            {
                                portList[i] |= PORT_MONITOR_INSPECT;
                                /* port specific rule */
                                for (otn = rtn->down; otn; otn = otn->next)
                                {
                                    /* Look for an OTN with flow or flowbits keyword */
                                    if (Stream5OtnHasFlowOrFlowbit(otn))
                                    {
                                        portList[i] |= PORT_MONITOR_SESSION;
                                    }
                                }
                            }
                        }
                    }
                }
                free(port_array);
                port_array = NULL;

                if ((inspectSrc == -1) && (inspectDst == -1))
                {
                    /* any -> any rule */
                    if (any_any_flow == 0)
                    {
                        any_any_flow = Stream5AnyAnyFlow(portList, rtn, any_any_flow,
                                &pIgnoredRuleList, ignoreAnyAnyRules);
                    }
                }
#else
                sport = (int16_t)((rtn->hsp == rtn->lsp) ? rtn->hsp : -1);

                if (rtn->flags & ANY_SRC_PORT)
                {
                    sport = -1;
                }

                if (sport > 0 &&  rtn->not_sp_flag > 0 )
                {
                    sport = -1;
                }

                /* Set the source port to inspect */
                if (sport != -1)
                {
                    portList[sport] |= PORT_MONITOR_INSPECT;
                }

                dport = (int16_t)((rtn->hdp == rtn->ldp) ? rtn->hdp : -1);

                if (rtn->flags & ANY_DST_PORT)
                {
                    dport = -1;
                }

                if (dport > 0 && rtn->not_dp_flag > 0 )
                {
                    dport = -1;
                }

                /* Set the dest port to inspect */
                if (dport != -1)
                {
                    inspectDst = 1;
                    portList[dport] |= PORT_MONITOR_INSPECT;
                }

                if (inspectSrc || inspectDst)
                {
                    /* port specific rule */
                    for (otn = rtn->down; otn; otn = otn->next)
                    {
                        /* Look for an OTN with flow or flowbits keyword */
                        if (Stream5OtnHasFlowOrFlowbit(otn))
                        {
                            if (inspectSrc)
                            {
                                portList[sport] |= PORT_MONITOR_SESSION;
                            }
                            if (inspectDst)
                            {
                                portList[dport] |= PORT_MONITOR_SESSION;
                            }
                        }
                    }
                }
                else
                {
                    /* any -> any rule */
                    if (any_any_flow == 0)
                    {
                        any_any_flow = Stream5AnyAnyFlow(portList, rtn, any_any_flow,
                                &pIgnoredRuleList, ignoreAnyAnyRules);
                    }
                }
#endif /* PORTLISTS */
            } /* for (rtn=...) */
        }
    } /* for (rule=...) */

    /* If portscan is tracking TCP/UDP, need to create
     * sessions for all ports */
    if (((protocol == IPPROTO_UDP) && (ps_get_protocols() & PS_PROTO_UDP))
            || ((protocol == IPPROTO_TCP)  && (ps_get_protocols() & PS_PROTO_TCP)))
    {
        int j;
        for (j=0; j<MAX_PORTS; j++)
        {
            portList[j] |= PORT_MONITOR_SESSION;
        }
    }

    if (any_any_flow == 1)
    {
        LogMessage("Warning: 'ignore_any_rules' option for Stream5 %s "
            "disabled because of %s rule with flow or flowbits option\n", 
            protocolName, protocolName);
    }
    else if (pIgnoredRuleList)
    {
        LogMessage("Warning: Rules (GID:SID) effectively ignored because of "
            "'ignore_any_rules' option for Stream5 %s:\n", protocolName);
        printIgnoredRules(pIgnoredRuleList, any_any_flow);
    }
}

/**Determines whether any_any_flow should be ignored or not.
 *
 * Dont ignore any_any_flows if flow bit is set on an any_any_flow, 
 * or ignoreAnyAnyRules is not set.
 * @param portList port list
 * @param rtn Rule tree node
 * @param any_any_flow - set if any_any_flow is ignored,0 otherwise
 * @param ppIgnoredRuleList
 * @param ignoreAnyAnyRules
 * @returns
 */
int Stream5AnyAnyFlow(
        u_int8_t *portList, 
        RuleTreeNode *rtn, 
        int any_any_flow,
        IgnoredRuleList **ppIgnoredRuleList,
        int ignoreAnyAnyRules
        )
{
    OptTreeNode *otn;
    int i;

    /**if any_any_flow is set then following code has no effect.*/
    if (any_any_flow)
    {
        return any_any_flow;
    }

    for (otn = rtn->down; otn; otn = otn->next)
    {
        /* Look for an OTN with flow or flowbits keyword */
        if (Stream5OtnHasFlowOrFlowbit(otn))
        {
            for (i=1;i<=MAX_PORTS;i++)
            {
                /* track sessions for ALL ports becuase
                 * of any -> any with flow/flowbits */
                portList[i] |= PORT_MONITOR_SESSION;
            }
            any_any_flow = 1;
            break;
        }
        else if (any_any_flow == 0)
        {
            if (!ignoreAnyAnyRules)
            {
                /* Not ignoring any any rules... */
                break;
            }

            /* if not, then ignore the content/pcre/etc */
            if (otn->ds_list[PLUGIN_PATTERN_MATCH] ||
                otn->ds_list[PLUGIN_PATTERN_MATCH_OR] ||
                otn->ds_list[PLUGIN_PATTERN_MATCH_URI] ||
#ifdef DYNAMIC_PLUGIN
                DynamicHasContent(otn) ||
                DynamicHasByteTest(otn) ||
                DynamicHasPCRE(otn) ||
#endif
                otn->ds_list[PLUGIN_BYTE_TEST] ||
                otn->ds_list[PLUGIN_PCRE])
            {
                /* Ignoring this rule.... */
                addRuleToIgnoreList(ppIgnoredRuleList, otn);
            }
        }
    } /* for (otn=...) */

    return any_any_flow;
}

/**add rule to the ignore rule list.
 */
static void addRuleToIgnoreList(IgnoredRuleList **ppIgnoredRuleList, OptTreeNode *otn)
{
    IgnoredRuleList *ignored_rule;

    ignored_rule = SnortAlloc(sizeof(*ignored_rule));
    ignored_rule->otn = otn;
    ignored_rule->next = *ppIgnoredRuleList;
    *ppIgnoredRuleList = ignored_rule;
}


/**print the ignored rule list.
 */
static void printIgnoredRules(
        IgnoredRuleList *pIgnoredRuleList,
        int any_any_flow
        )
{
    char six_sids = 0;
    int sids_ignored = 0;
    char buf[STD_BUF];
    IgnoredRuleList *ignored_rule;
    IgnoredRuleList *next_ignored_rule;

    buf[0] = '\0';

    for (ignored_rule = pIgnoredRuleList; ignored_rule != NULL; )
    {
        if (any_any_flow == 0)
        {
            if (six_sids == 1)
            {
                SnortSnprintfAppend(buf, STD_BUF-1, "\n");
                LogMessage(buf);
                six_sids = 0;
            }

            if (sids_ignored == 0)
            {
                SnortSnprintf(buf, STD_BUF-1, "    %d:%d",
                        ignored_rule->otn->sigInfo.generator,
                        ignored_rule->otn->sigInfo.id);
            }
            else
            {
                SnortSnprintfAppend(buf, STD_BUF-1, ", %d:%d", 
                        ignored_rule->otn->sigInfo.generator,
                        ignored_rule->otn->sigInfo.id);
            }
            sids_ignored++;
            if (sids_ignored %6 == 0)
            {
                /* Have it print next time through */
                six_sids = 1;
                sids_ignored = 0;
            }
        }
        next_ignored_rule = ignored_rule->next;
        free(ignored_rule);
        ignored_rule = next_ignored_rule;
    }

    if (sids_ignored || six_sids)
    {
        SnortSnprintfAppend(buf, STD_BUF-1, "\n");
        LogMessage(buf);
    }
}
