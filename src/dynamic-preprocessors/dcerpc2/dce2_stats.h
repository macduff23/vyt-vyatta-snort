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
 * 
 ****************************************************************************/

#ifndef _DCE2_STATS_H_
#define _DCE2_STATS_H_

#include "dce2_utils.h"
#include "sf_types.h"

/********************************************************************
 * Structures
 ********************************************************************/
typedef struct _DCE2_Stats
{
    UINT64 sessions;
    UINT64 missed_bytes;
    UINT64 overlapped_bytes;
    UINT64 sessions_autodetected;
    UINT64 bad_autodetects;

#ifdef DEBUG
    UINT64 autoports[65535][DCE2_TRANS_TYPE__MAX];
#endif

    UINT64 smb_sessions;
    UINT64 smb_pkts;
    UINT64 smb_ignored_bytes;
    UINT64 smb_non_ipc_packets;
    UINT64 smb_nbss_not_message;

    UINT64 smb_ssx_chained;
    UINT64 smb_ssx_req;
    UINT64 smb_ssx_req_chained_loffx;
    UINT64 smb_ssx_req_chained_tc;
    UINT64 smb_ssx_req_chained_tcx;
    UINT64 smb_ssx_req_chained_tdis;
    UINT64 smb_ssx_req_chained_open;
    UINT64 smb_ssx_req_chained_openx;
    UINT64 smb_ssx_req_chained_ntcx;
    UINT64 smb_ssx_req_chained_close;
    UINT64 smb_ssx_req_chained_trans;
    UINT64 smb_ssx_req_chained_write;
    UINT64 smb_ssx_req_chained_readx;
    UINT64 smb_ssx_req_chained_other;
    UINT64 smb_ssx_resp;
    UINT64 smb_ssx_resp_chained_loffx;
    UINT64 smb_ssx_resp_chained_tc;
    UINT64 smb_ssx_resp_chained_tcx;
    UINT64 smb_ssx_resp_chained_tdis;
    UINT64 smb_ssx_resp_chained_open;
    UINT64 smb_ssx_resp_chained_openx;
    UINT64 smb_ssx_resp_chained_ntcx;
    UINT64 smb_ssx_resp_chained_close;
    UINT64 smb_ssx_resp_chained_trans;
    UINT64 smb_ssx_resp_chained_write;
    UINT64 smb_ssx_resp_chained_readx;
    UINT64 smb_ssx_resp_chained_other;

    UINT64 smb_loffx_chained;
    UINT64 smb_loffx_req;
    UINT64 smb_loffx_req_chained_ssx;
    UINT64 smb_loffx_req_chained_tcx;
    UINT64 smb_loffx_req_chained_tdis;
    UINT64 smb_loffx_req_chained_other;
    UINT64 smb_loffx_resp;
    UINT64 smb_loffx_resp_chained_ssx;
    UINT64 smb_loffx_resp_chained_tcx;
    UINT64 smb_loffx_resp_chained_tdis;
    UINT64 smb_loffx_resp_chained_other;

    UINT64 smb_tc_req;
    UINT64 smb_tc_resp;

    UINT64 smb_tcx_chained;
    UINT64 smb_tcx_req;
    UINT64 smb_tcx_req_chained_ssx;
    UINT64 smb_tcx_req_chained_loffx;
    UINT64 smb_tcx_req_chained_tdis;
    UINT64 smb_tcx_req_chained_open;
    UINT64 smb_tcx_req_chained_openx;
    UINT64 smb_tcx_req_chained_ntcx;
    UINT64 smb_tcx_req_chained_close;
    UINT64 smb_tcx_req_chained_trans;
    UINT64 smb_tcx_req_chained_write;
    UINT64 smb_tcx_req_chained_readx;
    UINT64 smb_tcx_req_chained_other;
    UINT64 smb_tcx_resp;
    UINT64 smb_tcx_resp_chained_ssx;
    UINT64 smb_tcx_resp_chained_loffx;
    UINT64 smb_tcx_resp_chained_tdis;
    UINT64 smb_tcx_resp_chained_open;
    UINT64 smb_tcx_resp_chained_openx;
    UINT64 smb_tcx_resp_chained_ntcx;
    UINT64 smb_tcx_resp_chained_close;
    UINT64 smb_tcx_resp_chained_trans;
    UINT64 smb_tcx_resp_chained_write;
    UINT64 smb_tcx_resp_chained_readx;
    UINT64 smb_tcx_resp_chained_other;

    UINT64 smb_tdis_req;
    UINT64 smb_tdis_resp;

    UINT64 smb_open_req;
    UINT64 smb_open_resp;

    UINT64 smb_openx_chained;
    UINT64 smb_openx_req;
    UINT64 smb_openx_req_chained_ssx;
    UINT64 smb_openx_req_chained_loffx;
    UINT64 smb_openx_req_chained_tc;
    UINT64 smb_openx_req_chained_tcx;
    UINT64 smb_openx_req_chained_tdis;
    UINT64 smb_openx_req_chained_open;
    UINT64 smb_openx_req_chained_openx;
    UINT64 smb_openx_req_chained_ntcx;
    UINT64 smb_openx_req_chained_close;
    UINT64 smb_openx_req_chained_write;
    UINT64 smb_openx_req_chained_readx;
    UINT64 smb_openx_req_chained_other;
    UINT64 smb_openx_resp;
    UINT64 smb_openx_resp_chained_ssx;
    UINT64 smb_openx_resp_chained_loffx;
    UINT64 smb_openx_resp_chained_tc;
    UINT64 smb_openx_resp_chained_tcx;
    UINT64 smb_openx_resp_chained_tdis;
    UINT64 smb_openx_resp_chained_open;
    UINT64 smb_openx_resp_chained_openx;
    UINT64 smb_openx_resp_chained_ntcx;
    UINT64 smb_openx_resp_chained_close;
    UINT64 smb_openx_resp_chained_write;
    UINT64 smb_openx_resp_chained_readx;
    UINT64 smb_openx_resp_chained_other;

    UINT64 smb_ntcx_chained;
    UINT64 smb_ntcx_req;
    UINT64 smb_ntcx_req_chained_ssx;
    UINT64 smb_ntcx_req_chained_loffx;
    UINT64 smb_ntcx_req_chained_tc;
    UINT64 smb_ntcx_req_chained_tcx;
    UINT64 smb_ntcx_req_chained_tdis;
    UINT64 smb_ntcx_req_chained_open;
    UINT64 smb_ntcx_req_chained_openx;
    UINT64 smb_ntcx_req_chained_ntcx;
    UINT64 smb_ntcx_req_chained_close;
    UINT64 smb_ntcx_req_chained_write;
    UINT64 smb_ntcx_req_chained_readx;
    UINT64 smb_ntcx_req_chained_other;
    UINT64 smb_ntcx_resp;
    UINT64 smb_ntcx_resp_chained_ssx;
    UINT64 smb_ntcx_resp_chained_loffx;
    UINT64 smb_ntcx_resp_chained_tc;
    UINT64 smb_ntcx_resp_chained_tcx;
    UINT64 smb_ntcx_resp_chained_tdis;
    UINT64 smb_ntcx_resp_chained_open;
    UINT64 smb_ntcx_resp_chained_openx;
    UINT64 smb_ntcx_resp_chained_ntcx;
    UINT64 smb_ntcx_resp_chained_close;
    UINT64 smb_ntcx_resp_chained_write;
    UINT64 smb_ntcx_resp_chained_readx;
    UINT64 smb_ntcx_resp_chained_other;

    UINT64 smb_close_req;
    UINT64 smb_close_resp;

    UINT64 smb_write_req;
    UINT64 smb_write_resp;

    UINT64 smb_writebr_req;
    UINT64 smb_writebr_resp;

    UINT64 smb_writex_chained;
    UINT64 smb_writex_req;
    UINT64 smb_writex_req_chained_ssx;
    UINT64 smb_writex_req_chained_loffx;
    UINT64 smb_writex_req_chained_tc;
    UINT64 smb_writex_req_chained_tcx;
    UINT64 smb_writex_req_chained_openx;
    UINT64 smb_writex_req_chained_ntcx;
    UINT64 smb_writex_req_chained_close;
    UINT64 smb_writex_req_chained_write;
    UINT64 smb_writex_req_chained_writex;
    UINT64 smb_writex_req_chained_read;
    UINT64 smb_writex_req_chained_readx;
    UINT64 smb_writex_req_chained_other;
    UINT64 smb_writex_resp;
    UINT64 smb_writex_resp_chained_ssx;
    UINT64 smb_writex_resp_chained_loffx;
    UINT64 smb_writex_resp_chained_tc;
    UINT64 smb_writex_resp_chained_tcx;
    UINT64 smb_writex_resp_chained_openx;
    UINT64 smb_writex_resp_chained_ntcx;
    UINT64 smb_writex_resp_chained_close;
    UINT64 smb_writex_resp_chained_write;
    UINT64 smb_writex_resp_chained_writex;
    UINT64 smb_writex_resp_chained_read;
    UINT64 smb_writex_resp_chained_readx;
    UINT64 smb_writex_resp_chained_other;

    UINT64 smb_writeclose_req;
    UINT64 smb_writeclose_resp;

    UINT64 smb_writecomplete_resp;

    UINT64 smb_trans_req;
    UINT64 smb_trans_sec_req;
    UINT64 smb_trans_resp;

    UINT64 smb_read_req;
    UINT64 smb_read_resp;

    UINT64 smb_readbr_req;
    UINT64 smb_readbr_resp;

    UINT64 smb_readx_chained;
    UINT64 smb_readx_req;
    UINT64 smb_readx_req_chained_ssx;
    UINT64 smb_readx_req_chained_loffx;
    UINT64 smb_readx_req_chained_tc;
    UINT64 smb_readx_req_chained_tcx;
    UINT64 smb_readx_req_chained_tdis;
    UINT64 smb_readx_req_chained_openx;
    UINT64 smb_readx_req_chained_ntcx;
    UINT64 smb_readx_req_chained_close;
    UINT64 smb_readx_req_chained_write;
    UINT64 smb_readx_req_chained_readx;
    UINT64 smb_readx_req_chained_other;
    UINT64 smb_readx_resp;
    UINT64 smb_readx_resp_chained_ssx;
    UINT64 smb_readx_resp_chained_loffx;
    UINT64 smb_readx_resp_chained_tc;
    UINT64 smb_readx_resp_chained_tcx;
    UINT64 smb_readx_resp_chained_tdis;
    UINT64 smb_readx_resp_chained_openx;
    UINT64 smb_readx_resp_chained_ntcx;
    UINT64 smb_readx_resp_chained_close;
    UINT64 smb_readx_resp_chained_write;
    UINT64 smb_readx_resp_chained_readx;
    UINT64 smb_readx_resp_chained_other;

    UINT64 smb_rename_req;
    UINT64 smb_rename_resp;

    UINT64 smb_other_req;
    UINT64 smb_other_resp;

    UINT64 tcp_sessions;
    UINT64 tcp_pkts;

    UINT64 udp_sessions;
    UINT64 udp_pkts;

    UINT64 http_proxy_sessions;
    UINT64 http_proxy_pkts;

    UINT64 http_server_sessions;
    UINT64 http_server_pkts;

    UINT64 co_pkts;
    UINT64 co_bind;
    UINT64 co_bind_ack;
    UINT64 co_alter_ctx;
    UINT64 co_alter_ctx_resp;
    UINT64 co_bind_nack;
    UINT64 co_request;
    UINT64 co_response;
    UINT64 co_cancel;
    UINT64 co_orphaned;
    UINT64 co_fault;
    UINT64 co_auth3;
    UINT64 co_shutdown;
    UINT64 co_reject;
    UINT64 co_ms_pdu;
    UINT64 co_other_req;
    UINT64 co_other_resp;
    UINT64 co_fragments;
    UINT64 co_max_frag_size;
    UINT64 co_reassembled;

    UINT64 cl_pkts;
    UINT64 cl_request;
    UINT64 cl_ack;
    UINT64 cl_cancel;
    UINT64 cl_cli_fack;
    UINT64 cl_ping;
    UINT64 cl_response;
    UINT64 cl_reject;
    UINT64 cl_cancel_ack;
    UINT64 cl_srv_fack;
    UINT64 cl_fault;
    UINT64 cl_nocall;
    UINT64 cl_working;
    UINT64 cl_other_req;
    UINT64 cl_other_resp;
    UINT64 cl_fragments;
    UINT64 cl_max_frag_size;
    UINT64 cl_reassembled;
    UINT64 cl_max_seqnum;

} DCE2_Stats;

/********************************************************************
 * Public function prototypes
 ********************************************************************/
void DCE2_StatsInit(void);
void DCE2_StatsFree(void);

#endif  /* _DCE2_STATS_H_ */

