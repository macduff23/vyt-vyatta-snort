/* $Id$ */
/*
 ** Portions Copyright (C) 1998-2009 Sourcefire, Inc.
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation; either version 2 of the License, or
 ** (at your option) any later version.
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
#ifdef GIDS
#include "snort.h"
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#ifndef Pru16
#define PRu16   3
#endif
#ifndef LIBNET_ERR_WARNING
#define LIBNET_ERR_WARNING  1
#define LIBNET_ERR_CRITICAL 2
#define LIBNET_ERR_FATAL    3
#endif


#include "decode.h"
#include "inline.h"
#include "inline_extern.h"
#include "rules.h"
#include "stream_api.h"
#include "spp_frag3.h"

#define PKT_BUFSIZE 65536

/* Most of the code related to libnet (resets and icmp unreach) was 
 * taken from sp_respond.c */

extern pcap_t *pcap_handle;

/* vars */
int libnet_nd;  /* libnet descriptor */
char errbuf[LIBNET_ERRBUF_SIZE];

Packet *tmpP;

u_char *l_tcp, *l_icmp;

#ifndef IPFW
pkt_msg_t *g_m = NULL;
#endif

/* predeclarations */
#ifndef IPFW
void HandlePacket(int pkt_id);
void TranslateToPcap(struct nfq_data *nfa, struct pcap_pkthdr *);
#else
void HandlePacket(void);
void TranslateToPcap(struct pcap_pkthdr *phdr, ssize_t len);
#endif /* IPFW */
void ResetIV(void);


int InlineModeSetPrivsAllowed(void)
{
	if (ScAdapterInlineMode())
        return 0;

    return 1;
}

#ifndef IPFW
void TranslateToPcap(struct nfq_data *nfa, struct pcap_pkthdr *phdr)
{
    static struct timeval ts;
    int iret;
    char *payload;

    iret = nfq_get_timestamp(nfa, &ts); 
    if (!iret) {
       phdr->ts.tv_sec = (long)(ts.tv_sec);
       phdr->ts.tv_usec = (long)(ts.tv_usec);
    } else {
       memset (&ts, 0, sizeof(struct timeval));
       gettimeofday(&ts, NULL);
       phdr->ts.tv_sec = ts.tv_sec;
       phdr->ts.tv_usec = ts.tv_usec;
    }
    
    phdr->caplen = phdr->len = nfq_get_payload(nfa, &payload);
}
#else
void TranslateToPcap(struct pcap_pkthdr *phdr, ssize_t len)
{
    static struct timeval t;
    memset (&t, 0, sizeof(struct timeval));
    gettimeofday(&t, NULL);
    phdr->ts.tv_sec = t.tv_sec;
    phdr->ts.tv_usec = t.tv_usec;
    phdr->caplen = len;
    phdr->len = len;

}
#endif


void ResetIV(void)
{
    iv.drop = 0;
    iv.reject = 0;
    iv.replace = 0;
}


/*
 *    Function: void InitInlinePostConfig
 *
 *    Purpose: perform initialization tasks that depend on the configfile
 *
 *    Args: none
 *    
 *    Returns: nothing void function
 */
void InitInlinePostConfig(void)
{
    int tcp_size = 0;
    int icmp_size = 0;

    //printf("InitInline stage 2: InitInlinePostConfig starting...\n");

    /* Let's initialize Libnet, but not if we are in
     * layer 2 resets mode, because we use the link
     * layer then... */
#ifndef IPFW
    if (ScLinkLayerResets())
    {
        tcp_size = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_TCP_H;
        icmp_size = 128 + LIBNET_ETH_H;
    }
    else
#endif
    {
        //printf("opening raw socket in IP-mode\n");

        if((libnet_nd = libnet_open_raw_sock(IPPROTO_RAW)) < 0)
        {
            fprintf(stdout, "InitInline: Could not open raw socket for libnet\n");
            exit(-1);
        }

        tcp_size = LIBNET_IP_H + LIBNET_TCP_H;
        icmp_size = 128;
    }

    /* init */
    l_tcp = calloc(tcp_size, sizeof(char));
    if (l_tcp == NULL)
    {
        perror("InitInline: Could not allocate l_tcp\n");
        exit(-1);
    }
    l_icmp = calloc(icmp_size, sizeof(char));
    if (l_icmp == NULL)
    {
        perror("InitInline: Could not allocate l_icmp\n");
        exit(-1);
    }


#ifndef IPFW
    if (ScLinkLayerResets())
    {    
        /* Building Layer 2 Reset Packets */
        printf("building cached link layer reset packets\n");
   
        libnet_build_ip(LIBNET_TCP_H, 0, libnet_get_prand(PRu16), 0, 255, 
                        IPPROTO_TCP, 0, 0, NULL, 0, l_tcp + LIBNET_ETH_H);

        libnet_build_tcp(0, 0, 0, 0, TH_RST|TH_ACK, 0, 0, NULL, 0,
                         l_tcp + LIBNET_ETH_H + LIBNET_IP_H);

        /* create icmp cached packet */
        libnet_build_ip(LIBNET_ICMP_UNREACH_H, 0, libnet_get_prand(PRu16), 0,
                        255, IPPROTO_ICMP, 0, 0, NULL, 0, l_icmp + LIBNET_ETH_H);
        libnet_build_icmp_unreach(3, 3, 0, 0, 0, 0, 0, 0, 0, 0, NULL, 0,
                                  l_icmp + LIBNET_ETH_H + LIBNET_IP_H);
    }
    else 
#endif
    {
        /* Building Socket Reset Packets */ 
        printf("building cached socket reset packets\n"); 
  
        libnet_build_ip(LIBNET_TCP_H, 0, libnet_get_prand(PRu16), 0, 255,
                        IPPROTO_TCP, 0, 0, NULL, 0, l_tcp);

        libnet_build_tcp(0, 0, 0, 0, TH_RST|TH_ACK, 0, 0, NULL, 0,
                         l_tcp + LIBNET_IP_H);

        /* create icmp cached packet */
        libnet_build_ip(LIBNET_ICMP_UNREACH_H, 0, libnet_get_prand(PRu16), 0,
                        255, IPPROTO_ICMP, 0, 0, NULL, 0, l_icmp);
        libnet_build_icmp_unreach(3, 3, 0, 0, 0, 0, 0, 0, 0, 0, NULL, 0,
                                  l_icmp + LIBNET_IP_H);
    }  
}

#ifndef IPFW
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{  
   struct pcap_pkthdr PHdr;
   char   *payload;
   struct nfqnl_msg_packet_hdr *ph;
   struct nfqnl_msg_packet_hw *hw;
   int pkt_id;
   pkt_msg_t pkt_msg;

   nfq_get_payload(nfa, &payload);

   ph = nfq_get_msg_packet_hdr(nfa);
   pkt_id = ntohl(ph->packet_id);

   hw = nfq_get_packet_hw(nfa);
   if (hw) {
       pkt_msg.hw_addrlen = ntohs(hw->hw_addrlen);
       memcpy(pkt_msg.hw_addr, hw->hw_addr,  pkt_msg.hw_addrlen);
   } else {
       memset (&pkt_msg, 0, sizeof(pkt_msg_t));
   }
   g_m = &pkt_msg;

   TranslateToPcap(nfa, &PHdr);
   ProcessPacket(NULL, &PHdr, (u_char *)payload, NULL);
   HandlePacket(pkt_id);

   return(0);
}
#endif 

/* InitInline is called before the Snort_inline configuration file is read. */
int InitInline(void)
{
    LogMessage("Initializing Inline mode \n");

#ifndef IPFW
    nfq_h = nfq_open();
    if (!nfq_h) {
        FatalError("[%d] error during nfq_open()\n", getpid());
    }

    if (nfq_unbind_pf(nfq_h, AF_INET) < 0) {
        FatalError("[%d] error during nfq_unbind_pf()\n", getpid());
    }

    if (nfq_bind_pf(nfq_h, AF_INET) < 0) {
        FatalError("[%d] error during nfq_bind_pf()\n", getpid());
    }

#ifdef SUP_IP6
    if (nfq_unbind_pf(nfq_h, AF_INET6) < 0) {
        FatalError("[%d] error during nfq_unbind_pf() AF_INET6\n", getpid());
    }

    if (nfq_bind_pf(nfqh, AF_INET6) < 0) {
        FatalError("[%d] error during nfq_bind_pf() AF_INET6\n", getpid());
    }
#endif /* SUP_IP6 */

    nfq_q_h = nfq_create_queue(nfq_h, nfqueue_num, &cb, NULL);
    if (!nfq_q_h) {
        FatalError("[%d] error during nfq_create_queue() (queue %d busy ?)\n",
            getpid(), nfqueue_num);
    }

    if (nfq_set_mode(nfq_q_h, NFQNL_COPY_PACKET, 0xffff) < 0) {
        FatalError("[%d] can't set packet_copy mode\n", getpid());
    }

#endif /* IPFW */

    ResetIV();

    /* Just in case someone wants to write to a pcap file
     * using DLT_RAW because iptables does not give us datalink layer. */
    pcap_handle = pcap_open_dead(DLT_RAW, SNAPLEN);

    return 0;
}

#ifndef IPFW
void nfqLoop(void)
{
    ssize_t status;
    char buf[PKT_BUFSIZE];
    int nfq_sd;
    
#ifdef DEBUG_GIDS
    printf("Reading Packets from nfq handle \n");
#endif

    nfq_sd = nfq_fd(nfq_h);

    while(1)
    {
        ResetIV();
        status = recv(nfq_sd, buf, sizeof(buf), 0);
        if (status < 0)
        {
            if (errno == EINTR || errno == EWOULDBLOCK) {
                SignalCheck();
            } else {
                LogMessage("[%d] packet recv contents failure: %s\n",getpid(), strerror(errno));
            }
        }
        /* man ipq_read tells us that when a timeout is specified
         * ipq_read will return 0 when it is interupted. */
        else if(status == 0)
        {
            /* Do the signal check. If we don't do this we will
             * evaluate the signal only when we receive an actual
             * packet. We don't want to depend on this. */
            if (SignalCheck())
            {
#ifndef SNORT_RELOAD
                Restart();
#endif
            }
        }
        else
        {
           nfq_handle_packet(nfq_h, buf, status);
        } /* if - else */
    } /* while() */
}
#else  // IPFW

#ifndef IPPROTO_DIVERT
# define IPPROTO_DIVERT 254
#endif

/* Loop reading packets from IPFW
   - borrowed mostly from the TCP-MSSD daemon in FreeBSD ports tree
    Questions, comments send to:  nick@rogness.net
*/
void IpfwLoop(void)
{
    uint8_t pkt[IP_MAXPACKET];
    struct pcap_pkthdr PHdr;
    ssize_t pktlen, hlen;
    struct ip *pip = (struct ip *)pkt;
    struct sockaddr_in sin;
    socklen_t sinlen;
    int s;
    int rtsock;
    int ifindex;
    fd_set fdset;
    ifindex = 0;
    rtsock = -1;

#ifdef DEBUG_GIDS
    printf("Reading Packets from ipfw divert socket \n");
#endif

    /* Build divert socket */
    if ((s = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1) 
    {
        perror("IpfwLoop: can't create divert socket");
        exit(-1);
    }

    /* Fill in necessary fields */
    bzero(&sin, sizeof(sin));
    sin.sin_family = PF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(ScDivertPort());

    /* Bind that biatch */
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) 
    {
        perror("IpfwLoop: can't bind divert socket");
        exit(-1);
    }

    /* Lets process the packet */
    while (1) 
    {
        ResetIV();
        FD_ZERO(&fdset);
        FD_SET(s, &fdset);
        if (rtsock != -1)
        {
            FD_SET(rtsock, &fdset);
        }

        if (select(32, &fdset, (fd_set *)NULL, (fd_set *)NULL, (struct timeval *)NULL) == -1)
        {
            printf("select failed");
            continue;
        }

        if (FD_ISSET(s, &fdset)) 
        {
            sinlen = sizeof(sin);

            if ((pktlen = recvfrom(s, pkt, sizeof(pkt), 0,(struct sockaddr *)&sin, &sinlen)) == -1)
            {
                if (errno != EINTR)
                {
                     printf("IpfwLoop: read from divert socket failed");
                     continue;
                }
            }

            hlen = pip->ip_hl << 2;

            TranslateToPcap(&PHdr,pktlen);
            PcapProcessPacket(NULL, &PHdr, pkt);
            HandlePacket();

	    /* If we don't drop and don't reject, reinject it back into ipfw,
  	     * otherwise, we just drop it
	    */
            if (! iv.drop && ! iv.reject)
            {
                if (sendto(s, pkt, pktlen, 0,(struct sockaddr *)&sin, sinlen) == -1)
                {
                    printf("IpfwLoop: write to divert socket failed");
                }
            }
         } /* end if */

    } /* end while */
}
#endif  // IPFW


/*
 *    Function: static void RejectSocket
 *
 *    Purpose: send a reject packet (tcp-reset or icmp-unreachable
 *
 *    Args: none
 *    
 *    Returns: nothing void function
 */
static void
RejectSocket(void)
{
    IPHdr *iph;
    TCPHdr *tcph;
    ICMPHdr *icmph;

    int proto;
    int size = 0;
    int payload_len = 0;

    iph = (IPHdr *)l_tcp;

    proto = tmpP->iph->ip_proto;
    iph->ip_src.s_addr = tmpP->iph->ip_dst.s_addr;
    iph->ip_dst.s_addr = tmpP->iph->ip_src.s_addr;

    switch(proto)
    {
        case IPPROTO_TCP:
            if (!tmpP->frag_flag)
            {
                size = LIBNET_IP_H + LIBNET_TCP_H;
                iph = (IPHdr *)l_tcp;
                tcph = (TCPHdr *)(l_tcp + LIBNET_IP_H);

                iph->ip_src.s_addr = tmpP->iph->ip_dst.s_addr;
                iph->ip_dst.s_addr = tmpP->iph->ip_src.s_addr;

                tcph->th_sport = tmpP->tcph->th_dport;
                tcph->th_dport = tmpP->tcph->th_sport;
                tcph->th_seq = tmpP->tcph->th_ack;
                tcph->th_ack = htonl(ntohl(tmpP->tcph->th_seq) + 1);
                        
                //printf("Send TCP Rst in IP-mode.\n");
		    
                /* calculate the checksum */
                if (libnet_do_checksum(l_tcp, IPPROTO_TCP, LIBNET_TCP_H) == -1)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                 "SendTCPRST: libnet_do_checksum");
                    return;
                }
                /* write it to the socket */
                if(libnet_write_ip(libnet_nd, l_tcp, size) < size)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                 "SendTCPRST: libnet_write_ip");
                    return;
                }
            } /* end if !tmpP->frag_flag */
            break;

        case IPPROTO_UDP:
            if (!tmpP->frag_flag)
            {
                iph = (IPHdr *)l_icmp;
                icmph = (ICMPHdr *)(l_icmp + LIBNET_IP_H);
						
                iph->ip_src.s_addr = tmpP->iph->ip_dst.s_addr;
                iph->ip_dst.s_addr = tmpP->iph->ip_src.s_addr;

                if ((payload_len = ntohs(tmpP->iph->ip_len) - 
                    (IP_HLEN(tmpP->iph) << 2)) > 8)
                {
                    payload_len = 8;
                }

                memcpy((char *)icmph + LIBNET_ICMP_UNREACH_H, tmpP->iph, 
                       (IP_HLEN(tmpP->iph) << 2) + payload_len);
                        
                size = LIBNET_IP_H + LIBNET_ICMP_UNREACH_H + 
                       (IP_HLEN(tmpP->iph) << 2) + payload_len;

                iph->ip_len = htons(size);
                        
                /* calculate checksums */
                if (libnet_do_checksum(l_icmp, IPPROTO_ICMP, size - LIBNET_IP_H) == -1)
	        {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                 "SendICMPRST: libnet_do_checksum failed for IPPROTO_ICMP");
		    return;
		}
                             
                /* finally write to socket */ 
                if(libnet_write_ip(libnet_nd, l_icmp, size) < size)
                {
                    libnet_error(LIBNET_ERR_CRITICAL, 
                                 "SendICMPRST: libnet_write_ip");
                    return;
                }
            } /* end if !tmpP->frag_flag */
            break;
    } /* end switch(proto) */
}


/*
 *    Function: static void RejectLayer2(ipq_packet_msg_t *m)
 *
 *    Purpose: send a reject packet (tcp-reset or icmp-unreachable
 *
 *    Args: the ipq_packet_msg_t m for determining the output interface
 *          and the source mac for our packet.
 *    
 *    Returns: nothing void function
 *
 *    TODO: make it also work on *BSD.
 */
#ifdef SUPPORT_REJECT
#ifndef IPFW
static void
RejectLayer2(ipq_packet_msg_t *m)
{
    IPHdr *iph;
    TCPHdr *tcph;
    ICMPHdr *icmph;
    EtherHdr *eh;

    int proto;
    int size = 0;
    int payload_len = 0;

    /* pointer to the device to use: according to the libnet manpage
     * this should be u_char, but I get a compiler warning then.
     * Making it a char fixes that. VJ. */
    char *device = NULL;
    
    /* to get the mac address of the interface when in layer2 mode */
    struct ether_addr *link_addr;

    u_char enet_dst[6]; /* mac addr for creating the ethernet packet. */
    u_char enet_src[6]; /* mac addr for creating the ethernet packet. */

    struct libnet_link_int *network = NULL;    /* pointer to link interface struct */

    int i = 0;

    iph = (IPHdr *)(l_tcp + LIBNET_ETH_H);


    proto = tmpP->iph->ip_proto;
    iph->ip_src.s_addr = tmpP->iph->ip_dst.s_addr;
    iph->ip_dst.s_addr = tmpP->iph->ip_src.s_addr;


    /* set the interface. For Nat/Ip-mode the device we use to send a reset to the offender
     * is the device on which the packet entered. For bridge-mode indev and outdev are always
     * equal, so we use indev as well. There is one rare exception to this... if on the Snort_
     * inline box a client is run that causes a reset, indev is not set but outdev. */
    if(m->indev_name[0] != '\0')
        device = m->indev_name;
    else
        device = m->outdev_name;
        

    /* Let's initialize Libnet */
    if((network = libnet_open_link_interface(device, errbuf)) == NULL)
    {
        libnet_error(LIBNET_ERR_FATAL,
	             "libnet_open_link_interface for device %s failed: %s\n",
		     device, errbuf);
        return;
    }
    /* lets get the mac addr of the interface */
    if(!(link_addr = libnet_get_hwaddr(network, device, errbuf)))
    {
        libnet_error(LIBNET_ERR_FATAL,
                     "libnet_get_hwaddr failed: %s\n",
		     errbuf);
        return;
    }
    /* copy the mac: the src is set the the interface mac
     * but only if the mac wasn't supplied in the configfile */
    if ((snort_conf->enet_src[0] == 0) && (snort_conf->enet_src[1] == 0) &&
        (snort_conf->enet_src[2] == 0) && (snort_conf->enet_src[3] == 0) &&
        (snort_conf->enet_src[4] == 0) && (snort_conf->enet_src[5] == 0))
    {
        /* either user set mac as 00:00:00:00:00:00 or it is blank */   
        for(i = 0; i < 6; i++)
            enet_src[i] = link_addr->ether_addr_octet[i];
    }
    else
    {
        for(i = 0; i < 6; i++)  
            enet_src[i] = snort_conf->enet_src[i];    
    } 
    /* copy the mac: the old src now becomes dst */
    for(i = 0; i < 6; i++)
        enet_dst[i] = m->hw_addr[i];

    //printf("reset src mac: %02X:%02X:%02X:%02X:%02X:%02X\n", enet_src[0],enet_src[1],enet_src[2],enet_src[3],enet_src[4],enet_src[5]);
    //printf("reset dst mac: %02X:%02X:%02X:%02X:%02X:%02X\n", enet_dst[0],enet_dst[1],enet_dst[2],enet_dst[3],enet_dst[4],enet_dst[5]);

    switch(proto)
    {
        case IPPROTO_TCP:
            if (!tmpP->frag_flag)
            {
                size = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_TCP_H;
                eh = (EtherHdr *)l_tcp;
                iph = (IPHdr *)(l_tcp + LIBNET_ETH_H);
                tcph = (TCPHdr *)(l_tcp + LIBNET_ETH_H + LIBNET_IP_H);

                iph->ip_src.s_addr = tmpP->iph->ip_dst.s_addr;
                iph->ip_dst.s_addr = tmpP->iph->ip_src.s_addr;

                tcph->th_sport = tmpP->tcph->th_dport;
                tcph->th_dport = tmpP->tcph->th_sport;
                tcph->th_seq = tmpP->tcph->th_ack;
                tcph->th_ack = htonl(ntohl(tmpP->tcph->th_seq) + 1);
                        
                //printf("Send TCP Rst in Bridge-mode.\n");

                /* calculate the checksums */
                if (libnet_do_checksum(l_tcp + LIBNET_ETH_H, IPPROTO_TCP, LIBNET_TCP_H) == -1)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
            	                "SendEthTCPRST: libnet_do_checksum failed for LIBNET_TCP_H");
                    return;
                }
                if (libnet_do_checksum(l_tcp + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H) == -1)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                 "SendEthTCPRST: libnet_do_checksum failed for LIBNET_IPV4_H");
                    return;
                }
                /* build the ethernet packet */
                if (libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP, NULL, 0, l_tcp) == -1)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                 "SendEthTCPRST: libnet_build_ethernet");
                    return;
                }
                /* finally write it to the link */
                if(libnet_write_link_layer(network, device, l_tcp, size) < size)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                 "SendEthTCPRST: libnet_write_link_layer");
                    return;
                }
            } /* end if !tmpP->frag_flag */
            break;

        case IPPROTO_UDP:
            if (!tmpP->frag_flag)
            {
                eh = (EtherHdr *)l_icmp; 
                iph = (IPHdr *)(l_icmp + LIBNET_ETH_H);
                icmph = (ICMPHdr *) (l_icmp + LIBNET_ETH_H + LIBNET_IP_H);
						
                iph->ip_src.s_addr = tmpP->iph->ip_dst.s_addr;
                iph->ip_dst.s_addr = tmpP->iph->ip_src.s_addr;

                if ((payload_len = ntohs(tmpP->iph->ip_len) - 
                    (IP_HLEN(tmpP->iph) << 2)) > 8)
                {
                    payload_len = 8;
                }

                memcpy((char *)icmph + LIBNET_ICMP_UNREACH_H, tmpP->iph, 
                   (IP_HLEN(tmpP->iph) << 2) + payload_len);
                        
                size = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_ICMP_UNREACH_H + 
                       (IP_HLEN(tmpP->iph) << 2) + payload_len;

                iph->ip_len = htons(size);
                        
                /* calculate the checksums */
                if (libnet_do_checksum(l_icmp + LIBNET_ETH_H, IPPROTO_ICMP, size - LIBNET_IP_H) == -1)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                 "SendEthICMPRST: libnet_do_checksum failed for IPPROTO_ICMP");
		    return;
                }
                if (libnet_do_checksum(l_icmp + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H) == -1)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                 "SendEthICMPRST: libnet_do_checksum failed for IPPROTO_IP");
		    return;
                }
                        
                /* build the ethernet packet */
                if (libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP, NULL, 0, l_icmp) == -1)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                "SendEthICMPRST: libnet_build_ethernet");
                    return;
                }
                        
                /* finally write it to the link */
                //printf("Send ICMP Rst in Bridge-mode.\n");
 
                if(libnet_write_link_layer(network, device, l_icmp, size) < size)
                {
                    libnet_error(LIBNET_ERR_CRITICAL,
                                "SendEthICMPRST: libnet_write_link_layer");
                    return;
                }
            }
            break;
    } /* end switch(proto) */

    /* clean up file-descriptors for the next time we call RejectLayer2 */ 
    if((libnet_close_link_interface(network)) == -1)
    {
      libnet_error(LIBNET_ERR_CRITICAL,
                   "libnet_close_link_interface error\n");
    }
}
#endif  // IPFW

#endif // SUPPORT_REJECT

#ifndef IPFW
void HandlePacket(int pkt_id)
#else
void HandlePacket(void)
#endif
{
#ifndef IPFW
    int status;
#endif

    if (iv.drop)
    {
#ifndef IPFW
        status = nfq_set_verdict(nfq_q_h, pkt_id, NF_DROP, 0, NULL);
        if (status < 0)
        {
            fprintf(stderr,"NF_DROP: ");
        }
#endif

#ifdef SUPPORT_REJECT
        if (iv.reject)
        {
#ifndef IPFW
            if (ScLinkLayerResets())
            {
                RejectLayer2(m);
            }
            else
#endif
            {
                RejectSocket();
            }
        }
#endif // SUPPORT_REJECT
    }
#ifndef IPFW
    else if (!iv.replace)
    {
        status = nfq_set_verdict(nfq_q_h, pkt_id, NF_ACCEPT, 0, NULL);
        if (status < 0)
        {
            fprintf(stderr, "NF_ACCEPT: ");
        }
    }

    else
    {
        status = nfq_set_verdict(nfq_q_h, pkt_id, NF_ACCEPT, 0, NULL);
        if (status < 0)
        {
            fprintf(stderr, "NF_ACCEPT: ");
        }
    }
#endif
}
  
int InlineWasPacketDropped(void)
{
    if (iv.drop)
        return 1;
    
    return 0;
}

int InlineDrop(Packet *p)
{
    if(!ScInlineMode())
        return 0;
    iv.drop = 1;
    p->packet_flags |= PKT_INLINE_DROP;

    if (p->ssnptr && stream_api)
    {
        stream_api->drop_packet(p);

        if (!(p->packet_flags & PKT_STATELESS))
            stream_api->drop_traffic(p->ssnptr, SSN_DIR_BOTH);
    }

    //drop this and all following fragments
    frag3DropAllFragments(p);

    return 0;
}

int InlineReject(Packet *p)
{
    //printf("InlineReject(): rejecting\n");
    iv.reject = 1;
    iv.drop = 1;
    tmpP = p;
    return 0;
}

int InlineAccept(void)
{
    iv.drop = 0;
    return 0;
}

int InlineReplace(void)
{
    iv.replace = 1;
    return 0;
}

#else  // GIDS

#include "snort.h"
#include "stream_api.h"
#include "spp_frag3.h"

#ifndef WIN32
extern int g_drop_pkt;
#endif

int InlineModeSetPrivsAllowed(void)
{
    return 1;
}

int InlineWasPacketDropped(void)
{
#ifndef WIN32
    if (g_drop_pkt)
        return 1;
#endif
    
    return 0;
}

int InlineDrop(Packet *p)
{
    if(!ScInlineMode())
        return 0;

#ifndef WIN32
    g_drop_pkt = 1;
#endif
    
    p->packet_flags |= PKT_INLINE_DROP;

    if (p->ssnptr && stream_api)
    {
        stream_api->drop_packet(p);

        if (!(p->packet_flags & PKT_STATELESS))
            stream_api->drop_traffic(p->ssnptr, SSN_DIR_BOTH);
    }
    
    //drop this and all following fragments
    frag3DropAllFragments(p);
    return 0;
}
#endif /* GIDS */

