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

#include "spp_dce2.h"
#include "dce2_memory.h"
#include "dce2_list.h"
#include "dce2_utils.h"
#include "dce2_config.h"
#include "dce2_roptions.h"
#include "dce2_stats.h"
#include "dce2_event.h"
#include "snort_dce2.h"
#include "preprocids.h"
#include "profiler.h"
#include "sfrt.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "stream_api.h"

/********************************************************************
 * Global variables
 ********************************************************************/
#ifdef PERF_PROFILING
PreprocStats dce2_pstat_main;
PreprocStats dce2_pstat_session;
PreprocStats dce2_pstat_detect;
PreprocStats dce2_pstat_log;
PreprocStats dce2_pstat_smb_seg;
PreprocStats dce2_pstat_smb_trans;
PreprocStats dce2_pstat_smb_uid;
PreprocStats dce2_pstat_smb_tid;
PreprocStats dce2_pstat_smb_fid;
PreprocStats dce2_pstat_co_seg;
PreprocStats dce2_pstat_co_frag;
PreprocStats dce2_pstat_co_reass;
PreprocStats dce2_pstat_co_ctx;
PreprocStats dce2_pstat_cl_acts;
PreprocStats dce2_pstat_cl_frag;
PreprocStats dce2_pstat_cl_reass;
#endif

/********************************************************************
 * Extern variables
 ********************************************************************/
extern DCE2_ServerConfig *dconfig;
extern table_t *dce2_sconfigs;      /* Routing table with server configurations */
extern DCE2_Stats dce2_stats;
extern DCE2_Memory dce2_memory;
extern char **dce2_trans_strs;
extern DynamicPreprocessorData _dpd;
extern DCE2_CStack *dce2_pkt_stack;
extern DCE2_ProtoIds dce2_proto_ids;

/********************************************************************
 * Macros
 ********************************************************************/
#ifdef PERF_PROFILING
#define DCE2_PSTAT__MAIN       "DceRpcMain"
#define DCE2_PSTAT__SESSION    "DceRpcSession"
#define DCE2_PSTAT__DETECT     "DceRpcDetect"
#define DCE2_PSTAT__LOG        "DceRpcLog"
#define DCE2_PSTAT__SMB_SEG    "DceRpcSmbSeg"
#define DCE2_PSTAT__SMB_TRANS  "DceRpcSmbTrans"
#define DCE2_PSTAT__SMB_UID    "DceRpcSmbUid"
#define DCE2_PSTAT__SMB_TID    "DceRpcSmbTid"
#define DCE2_PSTAT__SMB_FID    "DceRpcSmbFid"
#define DCE2_PSTAT__CO_SEG     "DceRpcCoSeg"
#define DCE2_PSTAT__CO_FRAG    "DceRpcCoFrag"
#define DCE2_PSTAT__CO_REASS   "DceRpcCoReass"
#define DCE2_PSTAT__CO_CTX     "DceRpcCoCtx"
#define DCE2_PSTAT__CL_ACTS    "DceRpcClActs"
#define DCE2_PSTAT__CL_FRAG    "DceRpcClFrag"
#define DCE2_PSTAT__CL_REASS   "DceRpcClReass"
#endif  /* PERF_PROFILING */

/********************************************************************
 * Private function prototypes
 ********************************************************************/
static void DCE2_InitGlobal(char *);
static void DCE2_InitServer(char *);
static void DCE2_CheckConfig(void);
static void DCE2_Main(void *, void *);
static void DCE2_PrintStats(int);
static void DCE2_Reset(int, void *);
static void DCE2_ResetStats(int, void *);
static void DCE2_CleanExit(int, void *);

/********************************************************************
 * Function: DCE2_RegisterPreprocessor()
 *
 * Purpose: Registers the DCE/RPC preprocessor with Snort
 *
 * Arguments: None
 *
 * Returns: None
 *
 ********************************************************************/
void DCE2_RegisterPreprocessor(void)
{
    _dpd.registerPreproc(DCE2_GNAME, DCE2_InitGlobal);
    _dpd.registerPreproc(DCE2_SNAME, DCE2_InitServer);
}

/*********************************************************************
 * Function: DCE2_InitGlobal()
 *
 * Purpose: Initializes the global DCE/RPC preprocessor config.
 *
 * Arguments: snort.conf argument line for the DCE/RPC preprocessor.
 *
 * Returns: None
 *
 *********************************************************************/
static void DCE2_InitGlobal(char *args)
{
    if ((_dpd.streamAPI == NULL) || (_dpd.streamAPI->version != STREAM_API_VERSION5))
    {
        DCE2_Die("%s(%d) \"%s\" configuration: Stream5 must be enabled with "
                 "TCP and UDP tracking.",
                 *_dpd.config_file, *_dpd.config_line, DCE2_GNAME);
    }

    if (_dpd.isPreprocEnabled(PP_DCERPC))
    {
        DCE2_Die("%s(%d) \"%s\" configuration: Only one DCE/RPC preprocessor "
                 "can be configured.",
                 *_dpd.config_file, *_dpd.config_line, DCE2_GNAME);
    }

    DCE2_RegRuleOptions();

    DCE2_MemInit();
    DCE2_StatsInit();
    DCE2_EventsInit();

    /* Parse configuration args */
    DCE2_GlobalConfigure(args);

    /* Initialize reassembly packet */
    DCE2_InitRpkts();

    /* Register callbacks */
    _dpd.addPreprocConfCheck(DCE2_CheckConfig);
	_dpd.addPreproc(DCE2_Main, PRIORITY_APPLICATION, PP_DCE2, PROTO_BIT__TCP | PROTO_BIT__UDP);
    _dpd.registerPreprocStats(DCE2_GNAME, DCE2_PrintStats);
	_dpd.addPreprocReset(DCE2_Reset, NULL, PRIORITY_LAST, PP_DCE2);
	_dpd.addPreprocResetStats(DCE2_ResetStats, NULL, PRIORITY_LAST, PP_DCE2);
	_dpd.addPreprocExit(DCE2_CleanExit, NULL, PRIORITY_LAST, PP_DCE2);

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__MAIN, &dce2_pstat_main, 0, _dpd.totalPerfStats);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__SESSION, &dce2_pstat_session, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__LOG, &dce2_pstat_log, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__DETECT, &dce2_pstat_detect, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__SMB_SEG, &dce2_pstat_smb_seg, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__SMB_TRANS, &dce2_pstat_smb_trans, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__SMB_UID, &dce2_pstat_smb_uid, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__SMB_TID, &dce2_pstat_smb_tid, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__SMB_FID, &dce2_pstat_smb_fid, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__CO_SEG, &dce2_pstat_co_seg, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__CO_FRAG, &dce2_pstat_co_frag, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__CO_REASS, &dce2_pstat_co_reass, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__CO_CTX, &dce2_pstat_co_ctx, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__CL_ACTS, &dce2_pstat_cl_acts, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__CL_FRAG, &dce2_pstat_cl_frag, 1, &dce2_pstat_main);
    _dpd.addPreprocProfileFunc(DCE2_PSTAT__CL_REASS, &dce2_pstat_cl_reass, 1, &dce2_pstat_main);
#endif

#ifdef TARGET_BASED
    dce2_proto_ids.dcerpc = _dpd.findProtocolReference(DCE2_PROTO_REF_STR__DCERPC);
    if (dce2_proto_ids.dcerpc == SFTARGET_UNKNOWN_PROTOCOL)
        dce2_proto_ids.dcerpc = _dpd.addProtocolReference(DCE2_PROTO_REF_STR__DCERPC);

    /* smb and netbios-ssn refer to the same thing */
    dce2_proto_ids.nbss = _dpd.findProtocolReference(DCE2_PROTO_REF_STR__NBSS);
    if (dce2_proto_ids.nbss == SFTARGET_UNKNOWN_PROTOCOL)
        dce2_proto_ids.nbss = _dpd.addProtocolReference(DCE2_PROTO_REF_STR__NBSS);

    _dpd.streamAPI->set_service_filter_status(dce2_proto_ids.dcerpc, PORT_MONITOR_SESSION);
    _dpd.streamAPI->set_service_filter_status(dce2_proto_ids.nbss, PORT_MONITOR_SESSION);
#endif
}

/*********************************************************************
 * Function: DCE2_InitServer()
 *
 * Purpose: Initializes a DCE/RPC server configuration
 *
 * Arguments: snort.conf argument line for the DCE/RPC preprocessor.
 *
 * Returns: None
 *
 *********************************************************************/
static void DCE2_InitServer(char *args)
{
    /* Parse configuration args */
    DCE2_ServerConfigure(args);
}

/*********************************************************************
 * Function: DCE2_CheckConfig()
 *
 * Purpose: Verifies the DCE/RPC preprocessor configuration
 *
 * Arguments: None
 *
 * Returns: None
 *
 *********************************************************************/
static void DCE2_CheckConfig(void)
{
    if (dce2_dconfig == NULL)
        DCE2_CreateDefaultServerConfig();

    /* Register routing table memory */
    if (dce2_sconfigs != NULL)
        DCE2_RegMem(sfrt_usage(dce2_sconfigs), DCE2_MEM_TYPE__RT);

#ifdef TARGET_BASED
    if (!_dpd.isAdaptiveConfigured())
#endif
    {
        DCE2_ScCheckTransports();
    }
}

/*********************************************************************
 * Function: DCE2_Main()
 *
 * Purpose: Main entry point for DCE/RPC processing.
 *
 * Arguments:
 *  void * - pointer to packet structure
 *  void * - pointer to context 
 *
 * Returns: None
 *
 *********************************************************************/
static void DCE2_Main(void *pkt, void *context)
{
	SFSnortPacket *p = (SFSnortPacket *)pkt;
    PROFILE_VARS;

    DCE2_DEBUG_MSG(DCE2_DEBUG__ALL, "%s\n", DCE2_DEBUG__START_MSG);

#ifdef DEBUG
    if (DCE2_SsnFromServer(p))
    {
        DCE2_DEBUG_MSG(DCE2_DEBUG__MAIN, "Packet from server.\n");
    }
    else
    {
        DCE2_DEBUG_MSG(DCE2_DEBUG__MAIN, "Packet from client.\n");
    }
#endif

    /* No inspection to do */
    if ((p->payload_size == 0) || (p->payload == NULL))
    {
        DCE2_DEBUG_MSG(DCE2_DEBUG__MAIN, "No payload - not inspecting.\n");
        DCE2_DEBUG_MSG(DCE2_DEBUG__ALL, "%s\n", DCE2_DEBUG__END_MSG);
        return;
    }
    else if (p->stream_session_ptr == NULL)
    {
        DCE2_DEBUG_MSG(DCE2_DEBUG__MAIN, "No session pointer - not inspecting.\n");
        DCE2_DEBUG_MSG(DCE2_DEBUG__ALL, "%s\n", DCE2_DEBUG__END_MSG);
        return;
    }
    else if (!IsTCP(p) && !IsUDP(p))
    {
        DCE2_DEBUG_MSG(DCE2_DEBUG__MAIN, "Not UDP or TCP - not inspecting.\n");
        DCE2_DEBUG_MSG(DCE2_DEBUG__ALL, "%s\n", DCE2_DEBUG__END_MSG);
        return;
    }

    if (IsTCP(p))
    {
        if (DCE2_SsnIsMidstream(p))
        {
            DCE2_DEBUG_MSG(DCE2_DEBUG__MAIN, "Midstream - not inspecting.\n");
            DCE2_DEBUG_MSG(DCE2_DEBUG__ALL, "%s\n", DCE2_DEBUG__END_MSG);
            return;
        }
        else if (!DCE2_SsnIsEstablished(p))
        {
            DCE2_DEBUG_MSG(DCE2_DEBUG__MAIN, "Not established - not inspecting.\n");
            DCE2_DEBUG_MSG(DCE2_DEBUG__ALL, "%s\n", DCE2_DEBUG__END_MSG);
            return;
        }
    }

    PREPROC_PROFILE_START(dce2_pstat_main);

    if (DCE2_Process(p) == DCE2_RET__INSPECTED)
        DCE2_DisableDetect(p);

    PREPROC_PROFILE_END(dce2_pstat_main);

    DCE2_DEBUG_MSG(DCE2_DEBUG__ALL, "%s\n", DCE2_DEBUG__END_MSG);
}

/******************************************************************
 * Function: DCE2_PrintStats()
 *
 * Purpose: Print statistics being kept by the preprocessor.
 *
 * Arguments:
 *  int - whether Snort is exiting or not
 *       
 * Returns: None
 *
 ******************************************************************/ 
static void DCE2_PrintStats(int exiting)
{
    _dpd.logMsg("dcerpc2 Preprocessor Statistics\n");
    _dpd.logMsg("  Total sessions: "STDu64"\n", dce2_stats.sessions);
    if (dce2_stats.sessions > 0)
    {
        if (dce2_stats.missed_bytes > 0)
            _dpd.logMsg("  Missed bytes: "STDu64"\n", dce2_stats.missed_bytes);
        if (dce2_stats.overlapped_bytes > 0)
            _dpd.logMsg("  Overlapped bytes: "STDu64"\n", dce2_stats.overlapped_bytes);
        if (dce2_stats.sessions_autodetected > 0)
            _dpd.logMsg("  Total sessions autodetected: "STDu64"\n", dce2_stats.sessions_autodetected);
        if (dce2_stats.bad_autodetects > 0)
            _dpd.logMsg("  Bad autodetects: "STDu64"\n", dce2_stats.bad_autodetects);
#ifdef DEBUG
        {
            unsigned int port;
            int first = 1;

            for (port = 0; port < (sizeof(dce2_stats.autoports) / sizeof(dce2_stats.autoports[0])); port++)
            {
                DCE2_TransType ttype;

                for (ttype = DCE2_TRANS_TYPE__NONE; ttype < DCE2_TRANS_TYPE__MAX; ttype++)
                {
                    if ((dce2_stats.autoports[port][ttype] > 0) && (dce2_trans_strs[ttype] != NULL))
                    {
                        if (first)
                        {
                            _dpd.logMsg("\n");
                            _dpd.logMsg("  Autodetected ports:\n");
                            _dpd.logMsg("  %7s%15s%15s\n", "Port", "Transport", "Total");
                            first = 0;
                        }

                        _dpd.logMsg("  %7u%15s"FMTu64("15")"\n",
                                    port, dce2_trans_strs[ttype], dce2_stats.autoports[port][ttype]);
                    }
                }
            }
        }
#endif

        _dpd.logMsg("\n");
        _dpd.logMsg("  Transports\n");
        if (dce2_stats.smb_sessions > 0)
        {
            _dpd.logMsg("    SMB\n");
            _dpd.logMsg("      Total sessions: "STDu64"\n", dce2_stats.smb_sessions);
            _dpd.logMsg("      Packet stats\n");
            _dpd.logMsg("        Packets: "STDu64"\n", dce2_stats.smb_pkts);
            if (dce2_stats.smb_ignored_bytes > 0)
                _dpd.logMsg("        Ignored bytes: "STDu64"\n", dce2_stats.smb_ignored_bytes);
            if (dce2_stats.smb_non_ipc_packets > 0)
                _dpd.logMsg("        Not IPC packets (after tree connect): "STDu64"\n", dce2_stats.smb_non_ipc_packets);
            if (dce2_stats.smb_nbss_not_message > 0)
                _dpd.logMsg("        Not NBSS Session Message: "STDu64"\n", dce2_stats.smb_nbss_not_message);

            if ((dce2_stats.smb_ssx_req > 0) || (dce2_stats.smb_ssx_resp > 0))
            {
                _dpd.logMsg("        Session Setup AndX requests: "STDu64"\n", dce2_stats.smb_ssx_req);
                if (dce2_stats.smb_ssx_chained > 0)
                {
                    _dpd.logMsg("        Session Setup AndX chained requests\n");
                    if (dce2_stats.smb_ssx_req_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_ssx_req_chained_loffx);
                    if (dce2_stats.smb_ssx_req_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_ssx_req_chained_tc);
                    if (dce2_stats.smb_ssx_req_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_ssx_req_chained_tcx);
                    if (dce2_stats.smb_ssx_req_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_ssx_req_chained_tdis);
                    if (dce2_stats.smb_ssx_req_chained_open > 0)
                        _dpd.logMsg("          Open: "STDu64"\n", dce2_stats.smb_ssx_req_chained_open);
                    if (dce2_stats.smb_ssx_req_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_ssx_req_chained_openx);
                    if (dce2_stats.smb_ssx_req_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_ssx_req_chained_ntcx);
                    if (dce2_stats.smb_ssx_req_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_ssx_req_chained_close);
                    if (dce2_stats.smb_ssx_req_chained_trans > 0)
                        _dpd.logMsg("          Transact: "STDu64"\n", dce2_stats.smb_ssx_req_chained_trans);
                    if (dce2_stats.smb_ssx_req_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_ssx_req_chained_write);
                    if (dce2_stats.smb_ssx_req_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_ssx_req_chained_readx);
                    if (dce2_stats.smb_ssx_req_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_ssx_req_chained_other);
                }
                _dpd.logMsg("        Session Setup AndX responses: "STDu64"\n", dce2_stats.smb_ssx_resp);
                if (dce2_stats.smb_ssx_chained > 0)
                {
                    _dpd.logMsg("        Session Setup AndX chained responses\n");
                    if (dce2_stats.smb_ssx_resp_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_loffx);
                    if (dce2_stats.smb_ssx_resp_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_tc);
                    if (dce2_stats.smb_ssx_resp_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_tcx);
                    if (dce2_stats.smb_ssx_resp_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_tdis);
                    if (dce2_stats.smb_ssx_resp_chained_open > 0)
                        _dpd.logMsg("          Open: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_open);
                    if (dce2_stats.smb_ssx_resp_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_openx);
                    if (dce2_stats.smb_ssx_resp_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_ntcx);
                    if (dce2_stats.smb_ssx_resp_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_close);
                    if (dce2_stats.smb_ssx_resp_chained_trans > 0)
                        _dpd.logMsg("          Transact: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_trans);
                    if (dce2_stats.smb_ssx_resp_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_write);
                    if (dce2_stats.smb_ssx_resp_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_readx);
                    if (dce2_stats.smb_ssx_resp_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_ssx_resp_chained_other);
                }
            }

            if ((dce2_stats.smb_loffx_req > 0) || (dce2_stats.smb_loffx_resp > 0))
            {
                _dpd.logMsg("        Logoff AndX requests: "STDu64"\n", dce2_stats.smb_loffx_req);
                if (dce2_stats.smb_loffx_chained > 0)
                {
                    _dpd.logMsg("        Logoff AndX chained requests\n");
                    if (dce2_stats.smb_loffx_req_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_loffx_req_chained_ssx);
                    if (dce2_stats.smb_loffx_req_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_loffx_req_chained_tcx);
                    if (dce2_stats.smb_loffx_req_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_loffx_req_chained_tdis);
                    if (dce2_stats.smb_loffx_req_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_loffx_req_chained_other);
                }
                _dpd.logMsg("        Logoff AndX responses: "STDu64"\n", dce2_stats.smb_loffx_resp);
                if (dce2_stats.smb_loffx_chained > 0)
                {
                    _dpd.logMsg("        Logoff AndX chained responses\n");
                    if (dce2_stats.smb_loffx_resp_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_loffx_resp_chained_ssx);
                    if (dce2_stats.smb_loffx_resp_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_loffx_resp_chained_tcx);
                    if (dce2_stats.smb_loffx_resp_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_loffx_resp_chained_tdis);
                    if (dce2_stats.smb_loffx_resp_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_loffx_resp_chained_other);
                }
            }

            if ((dce2_stats.smb_tc_req > 0) || (dce2_stats.smb_tc_resp > 0))
            {
                _dpd.logMsg("        Tree Connect requests: "STDu64"\n", dce2_stats.smb_tc_req);
                _dpd.logMsg("        Tree Connect responses: "STDu64"\n", dce2_stats.smb_tc_resp);
            }

            if ((dce2_stats.smb_tcx_req > 0) || (dce2_stats.smb_tcx_resp > 0))
            {
                _dpd.logMsg("        Tree Connect AndX requests: "STDu64"\n", dce2_stats.smb_tcx_req);
                if (dce2_stats.smb_tcx_chained > 0)
                {
                    _dpd.logMsg("        Tree Connect AndX chained requests\n");
                    if (dce2_stats.smb_tcx_resp_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_tcx_req_chained_ssx);
                    if (dce2_stats.smb_tcx_resp_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_tcx_req_chained_loffx);
                    if (dce2_stats.smb_tcx_resp_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_tcx_req_chained_tdis);
                    if (dce2_stats.smb_tcx_resp_chained_open > 0)
                        _dpd.logMsg("          Open: "STDu64"\n", dce2_stats.smb_tcx_req_chained_open);
                    if (dce2_stats.smb_tcx_resp_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_tcx_req_chained_openx);
                    if (dce2_stats.smb_tcx_resp_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_tcx_req_chained_ntcx);
                    if (dce2_stats.smb_tcx_resp_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_tcx_req_chained_close);
                    if (dce2_stats.smb_tcx_resp_chained_trans > 0)
                        _dpd.logMsg("          Transact: "STDu64"\n", dce2_stats.smb_tcx_req_chained_trans);
                    if (dce2_stats.smb_tcx_resp_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_tcx_req_chained_write);
                    if (dce2_stats.smb_tcx_resp_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_tcx_req_chained_readx);
                    if (dce2_stats.smb_tcx_resp_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_tcx_req_chained_other);
                }
                _dpd.logMsg("        Tree Connect AndX responses: "STDu64"\n", dce2_stats.smb_tcx_resp);
                if (dce2_stats.smb_tcx_chained > 0)
                {
                    _dpd.logMsg("        Tree Connect AndX chained responses\n");
                    if (dce2_stats.smb_tcx_resp_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_ssx);
                    if (dce2_stats.smb_tcx_resp_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_loffx);
                    if (dce2_stats.smb_tcx_resp_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_tdis);
                    if (dce2_stats.smb_tcx_resp_chained_open > 0)
                        _dpd.logMsg("          Open: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_open);
                    if (dce2_stats.smb_tcx_resp_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_openx);
                    if (dce2_stats.smb_tcx_resp_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_ntcx);
                    if (dce2_stats.smb_tcx_resp_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_close);
                    if (dce2_stats.smb_tcx_resp_chained_trans > 0)
                        _dpd.logMsg("          Transact: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_trans);
                    if (dce2_stats.smb_tcx_resp_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_write);
                    if (dce2_stats.smb_tcx_resp_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_readx);
                    if (dce2_stats.smb_tcx_resp_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_tcx_resp_chained_other);
                }
            }

            if ((dce2_stats.smb_tdis_req > 0) || (dce2_stats.smb_tdis_resp > 0))
            {
                _dpd.logMsg("        Tree Disconnect requests: "STDu64"\n", dce2_stats.smb_tdis_req);
                _dpd.logMsg("        Tree Disconnect responses: "STDu64"\n", dce2_stats.smb_tdis_resp);
            }

            if ((dce2_stats.smb_open_req > 0) || (dce2_stats.smb_open_resp > 0))
            {
                _dpd.logMsg("        Open requests: "STDu64"\n", dce2_stats.smb_open_req);
                _dpd.logMsg("        Open responses: "STDu64"\n", dce2_stats.smb_open_resp);
            }

            if ((dce2_stats.smb_openx_req > 0) || (dce2_stats.smb_openx_resp > 0))
            {
                _dpd.logMsg("        Open AndX requests: "STDu64"\n", dce2_stats.smb_openx_req);
                if (dce2_stats.smb_openx_chained > 0)
                {
                    _dpd.logMsg("        Open AndX chained requests\n");
                    if (dce2_stats.smb_openx_req_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_openx_req_chained_ssx);
                    if (dce2_stats.smb_openx_req_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_openx_req_chained_loffx);
                    if (dce2_stats.smb_openx_req_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_openx_req_chained_tc);
                    if (dce2_stats.smb_openx_req_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_openx_req_chained_tcx);
                    if (dce2_stats.smb_openx_req_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_openx_req_chained_tdis);
                    if (dce2_stats.smb_openx_req_chained_open > 0)
                        _dpd.logMsg("          Open: "STDu64"\n", dce2_stats.smb_openx_req_chained_open);
                    if (dce2_stats.smb_openx_req_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_openx_req_chained_openx);
                    if (dce2_stats.smb_openx_req_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_openx_req_chained_ntcx);
                    if (dce2_stats.smb_openx_req_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_openx_req_chained_close);
                    if (dce2_stats.smb_openx_req_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_openx_req_chained_write);
                    if (dce2_stats.smb_openx_req_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_openx_req_chained_readx);
                    if (dce2_stats.smb_openx_req_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_openx_req_chained_other);
                }
                _dpd.logMsg("        Open AndX responses: "STDu64"\n", dce2_stats.smb_openx_resp);
                if (dce2_stats.smb_openx_chained > 0)
                {
                    _dpd.logMsg("        Open AndX chained responses\n");
                    if (dce2_stats.smb_openx_resp_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_openx_resp_chained_ssx);
                    if (dce2_stats.smb_openx_resp_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_openx_resp_chained_loffx);
                    if (dce2_stats.smb_openx_resp_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_openx_resp_chained_tc);
                    if (dce2_stats.smb_openx_resp_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_openx_resp_chained_tcx);
                    if (dce2_stats.smb_openx_resp_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_openx_resp_chained_tdis);
                    if (dce2_stats.smb_openx_resp_chained_open > 0)
                        _dpd.logMsg("          Open: "STDu64"\n", dce2_stats.smb_openx_resp_chained_open);
                    if (dce2_stats.smb_openx_resp_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_openx_resp_chained_openx);
                    if (dce2_stats.smb_openx_resp_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_openx_resp_chained_ntcx);
                    if (dce2_stats.smb_openx_resp_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_openx_resp_chained_close);
                    if (dce2_stats.smb_openx_resp_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_openx_resp_chained_write);
                    if (dce2_stats.smb_openx_resp_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_openx_resp_chained_readx);
                    if (dce2_stats.smb_openx_resp_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_openx_resp_chained_other);
                }
            }

            if ((dce2_stats.smb_ntcx_req > 0) || (dce2_stats.smb_ntcx_resp > 0))
            {
                _dpd.logMsg("        Nt Create AndX requests: "STDu64"\n", dce2_stats.smb_ntcx_req);
                if (dce2_stats.smb_ntcx_chained > 0)
                {
                    _dpd.logMsg("        Nt Create AndX chained requests\n");
                    if (dce2_stats.smb_ntcx_req_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_ssx);
                    if (dce2_stats.smb_ntcx_req_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_loffx);
                    if (dce2_stats.smb_ntcx_req_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_tc);
                    if (dce2_stats.smb_ntcx_req_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_tcx);
                    if (dce2_stats.smb_ntcx_req_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_tdis);
                    if (dce2_stats.smb_ntcx_req_chained_open > 0)
                        _dpd.logMsg("          Open: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_open);
                    if (dce2_stats.smb_ntcx_req_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_openx);
                    if (dce2_stats.smb_ntcx_req_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_ntcx);
                    if (dce2_stats.smb_ntcx_req_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_close);
                    if (dce2_stats.smb_ntcx_req_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_write);
                    if (dce2_stats.smb_ntcx_req_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_readx);
                    if (dce2_stats.smb_ntcx_req_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_ntcx_req_chained_other);
                }
                _dpd.logMsg("        Nt Create AndX responses: "STDu64"\n", dce2_stats.smb_ntcx_resp);
                if (dce2_stats.smb_ntcx_chained > 0)
                {
                    _dpd.logMsg("        Nt Create AndX chained responses\n");
                    if (dce2_stats.smb_ntcx_resp_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_ssx);
                    if (dce2_stats.smb_ntcx_resp_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_loffx);
                    if (dce2_stats.smb_ntcx_resp_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_tc);
                    if (dce2_stats.smb_ntcx_resp_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_tcx);
                    if (dce2_stats.smb_ntcx_resp_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_tdis);
                    if (dce2_stats.smb_ntcx_resp_chained_open > 0)
                        _dpd.logMsg("          Open: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_open);
                    if (dce2_stats.smb_ntcx_resp_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_openx);
                    if (dce2_stats.smb_ntcx_resp_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_ntcx);
                    if (dce2_stats.smb_ntcx_resp_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_close);
                    if (dce2_stats.smb_ntcx_resp_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_write);
                    if (dce2_stats.smb_ntcx_resp_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_readx);
                    if (dce2_stats.smb_ntcx_resp_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_ntcx_resp_chained_other);
                }
            }

            if ((dce2_stats.smb_close_req > 0) || (dce2_stats.smb_close_resp > 0))
            {
                _dpd.logMsg("        Close requests: "STDu64"\n", dce2_stats.smb_close_req);
                _dpd.logMsg("        Close responses: "STDu64"\n", dce2_stats.smb_close_resp);
            }

            if ((dce2_stats.smb_trans_req > 0) || (dce2_stats.smb_trans_resp > 0))
            {
                _dpd.logMsg("        Transact requests: "STDu64"\n", dce2_stats.smb_trans_req);
                if (dce2_stats.smb_trans_sec_req > 0)
                    _dpd.logMsg("        Transact Secondary requests: "STDu64"\n", dce2_stats.smb_trans_sec_req);
                _dpd.logMsg("        Transact responses: "STDu64"\n", dce2_stats.smb_trans_resp);
            }

            if ((dce2_stats.smb_write_req > 0) || (dce2_stats.smb_write_resp > 0))
            {
                _dpd.logMsg("        Write requests: "STDu64"\n", dce2_stats.smb_write_req);
                _dpd.logMsg("        Write responses: "STDu64"\n", dce2_stats.smb_write_resp);
            }

            if ((dce2_stats.smb_writebr_req > 0) || (dce2_stats.smb_writebr_resp > 0))
            {
                _dpd.logMsg("        Write Block Raw requests: "STDu64"\n", dce2_stats.smb_writebr_req);
                _dpd.logMsg("        Write Block Raw responses: "STDu64"\n", dce2_stats.smb_writebr_resp);
            }

            if ((dce2_stats.smb_writex_req > 0) || (dce2_stats.smb_writex_resp > 0))
            {
                _dpd.logMsg("        Write AndX requests: "STDu64"\n", dce2_stats.smb_writex_req);
                if (dce2_stats.smb_writex_chained > 0)
                {
                    _dpd.logMsg("        Write AndX chained requests\n");
                    if (dce2_stats.smb_writex_req_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_writex_req_chained_ssx);
                    if (dce2_stats.smb_writex_req_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_writex_req_chained_loffx);
                    if (dce2_stats.smb_writex_req_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_writex_req_chained_tc);
                    if (dce2_stats.smb_writex_req_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_writex_req_chained_tcx);
                    if (dce2_stats.smb_writex_req_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_writex_req_chained_openx);
                    if (dce2_stats.smb_writex_req_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_writex_req_chained_ntcx);
                    if (dce2_stats.smb_writex_req_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_writex_req_chained_close);
                    if (dce2_stats.smb_writex_req_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_writex_req_chained_write);
                    if (dce2_stats.smb_writex_req_chained_writex > 0)
                        _dpd.logMsg("          Write AndX: "STDu64"\n", dce2_stats.smb_writex_req_chained_writex);
                    if (dce2_stats.smb_writex_req_chained_read > 0)
                        _dpd.logMsg("          Read: "STDu64"\n", dce2_stats.smb_writex_req_chained_read);
                    if (dce2_stats.smb_writex_req_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_writex_req_chained_readx);
                    if (dce2_stats.smb_writex_req_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_writex_req_chained_other);
                }
                _dpd.logMsg("        Write AndX responses: "STDu64"\n", dce2_stats.smb_writex_resp);
                if (dce2_stats.smb_writex_chained > 0)
                {
                    _dpd.logMsg("        Write AndX chained responses\n");
                    if (dce2_stats.smb_writex_resp_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_writex_resp_chained_ssx);
                    if (dce2_stats.smb_writex_resp_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_writex_resp_chained_loffx);
                    if (dce2_stats.smb_writex_resp_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_writex_resp_chained_tc);
                    if (dce2_stats.smb_writex_resp_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_writex_resp_chained_tcx);
                    if (dce2_stats.smb_writex_resp_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_writex_resp_chained_openx);
                    if (dce2_stats.smb_writex_resp_chained_ntcx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_writex_resp_chained_ntcx);
                    if (dce2_stats.smb_writex_resp_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_writex_resp_chained_close);
                    if (dce2_stats.smb_writex_resp_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_writex_resp_chained_write);
                    if (dce2_stats.smb_writex_resp_chained_writex > 0)
                        _dpd.logMsg("          Write AndX: "STDu64"\n", dce2_stats.smb_writex_resp_chained_writex);
                    if (dce2_stats.smb_writex_resp_chained_read > 0)
                        _dpd.logMsg("          Read: "STDu64"\n", dce2_stats.smb_writex_resp_chained_read);
                    if (dce2_stats.smb_writex_resp_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_writex_resp_chained_readx);
                    if (dce2_stats.smb_writex_resp_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_writex_resp_chained_other);
                }
            }

            if ((dce2_stats.smb_writeclose_req > 0) || (dce2_stats.smb_writeclose_resp > 0))
            {
                _dpd.logMsg("        Write and Close requests: "STDu64"\n", dce2_stats.smb_writeclose_req);
                _dpd.logMsg("        Write and Close responses: "STDu64"\n", dce2_stats.smb_writeclose_resp);
            }

            if (dce2_stats.smb_writecomplete_resp > 0)
                _dpd.logMsg("        Write Complete responses: "STDu64"\n", dce2_stats.smb_writecomplete_resp);

            if ((dce2_stats.smb_read_req > 0) || (dce2_stats.smb_read_resp > 0))
            {
                _dpd.logMsg("        Read requests: "STDu64"\n", dce2_stats.smb_read_req);
                _dpd.logMsg("        Read responses: "STDu64"\n", dce2_stats.smb_read_resp);
            }

            if ((dce2_stats.smb_readbr_req > 0) || (dce2_stats.smb_readbr_resp > 0))
            {
                _dpd.logMsg("        Read Block Raw requests: "STDu64"\n", dce2_stats.smb_readbr_req);
                _dpd.logMsg("        Read Block Raw responses: "STDu64"\n", dce2_stats.smb_readbr_resp);
            }

            if ((dce2_stats.smb_readx_req > 0) || (dce2_stats.smb_readx_resp > 0))
            {
                _dpd.logMsg("        Read AndX requests: "STDu64"\n", dce2_stats.smb_readx_req);
                if (dce2_stats.smb_readx_chained > 0)
                {
                    _dpd.logMsg("        Read AndX chained requests\n");
                    if (dce2_stats.smb_readx_req_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_readx_req_chained_ssx);
                    if (dce2_stats.smb_readx_req_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_readx_req_chained_loffx);
                    if (dce2_stats.smb_readx_req_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_readx_req_chained_tc);
                    if (dce2_stats.smb_readx_req_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_readx_req_chained_tcx);
                    if (dce2_stats.smb_readx_req_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_readx_req_chained_tdis);
                    if (dce2_stats.smb_readx_req_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_readx_req_chained_openx);
                    if (dce2_stats.smb_readx_req_chained_readx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_readx_req_chained_readx);
                    if (dce2_stats.smb_readx_req_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_readx_req_chained_close);
                    if (dce2_stats.smb_readx_req_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_readx_req_chained_write);
                    if (dce2_stats.smb_readx_req_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_readx_req_chained_readx);
                    if (dce2_stats.smb_readx_req_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_readx_req_chained_other);
                }
                _dpd.logMsg("        Read AndX responses: "STDu64"\n", dce2_stats.smb_readx_resp);
                if (dce2_stats.smb_readx_chained > 0)
                {
                    _dpd.logMsg("        Read AndX chained responses\n");
                    if (dce2_stats.smb_readx_resp_chained_ssx > 0)
                        _dpd.logMsg("          Session Setup AndX: "STDu64"\n", dce2_stats.smb_readx_resp_chained_ssx);
                    if (dce2_stats.smb_readx_resp_chained_loffx > 0)
                        _dpd.logMsg("          Logoff AndX: "STDu64"\n", dce2_stats.smb_readx_resp_chained_loffx);
                    if (dce2_stats.smb_readx_resp_chained_tc > 0)
                        _dpd.logMsg("          Tree Connect: "STDu64"\n", dce2_stats.smb_readx_resp_chained_tc);
                    if (dce2_stats.smb_readx_resp_chained_tcx > 0)
                        _dpd.logMsg("          Tree Connect AndX: "STDu64"\n", dce2_stats.smb_readx_resp_chained_tcx);
                    if (dce2_stats.smb_readx_resp_chained_tdis > 0)
                        _dpd.logMsg("          Tree Disconnect: "STDu64"\n", dce2_stats.smb_readx_resp_chained_tdis);
                    if (dce2_stats.smb_readx_resp_chained_openx > 0)
                        _dpd.logMsg("          Open AndX: "STDu64"\n", dce2_stats.smb_readx_resp_chained_openx);
                    if (dce2_stats.smb_readx_resp_chained_readx > 0)
                        _dpd.logMsg("          Nt Create AndX: "STDu64"\n", dce2_stats.smb_readx_resp_chained_readx);
                    if (dce2_stats.smb_readx_resp_chained_close > 0)
                        _dpd.logMsg("          Close: "STDu64"\n", dce2_stats.smb_readx_resp_chained_close);
                    if (dce2_stats.smb_readx_resp_chained_write > 0)
                        _dpd.logMsg("          Write: "STDu64"\n", dce2_stats.smb_readx_resp_chained_write);
                    if (dce2_stats.smb_readx_resp_chained_readx > 0)
                        _dpd.logMsg("          Read AndX: "STDu64"\n", dce2_stats.smb_readx_resp_chained_readx);
                    if (dce2_stats.smb_readx_resp_chained_other > 0)
                        _dpd.logMsg("          Other: "STDu64"\n", dce2_stats.smb_readx_resp_chained_other);
                }
            }

            if ((dce2_stats.smb_rename_req > 0) || (dce2_stats.smb_rename_resp > 0))
            {
                _dpd.logMsg("        Rename requests: "STDu64"\n", dce2_stats.smb_rename_req);
                _dpd.logMsg("        Rename responses: "STDu64"\n", dce2_stats.smb_rename_resp);
            }

            if ((dce2_stats.smb_other_req > 0) || (dce2_stats.smb_other_resp > 0))
            {
                _dpd.logMsg("        SMB other command requests: "STDu64"\n", dce2_stats.smb_other_req);
                _dpd.logMsg("        SMB other command responses: "STDu64"\n", dce2_stats.smb_other_resp);
            }

#ifdef DEBUG
            _dpd.logMsg("      Memory stats (bytes)\n");
            _dpd.logMsg("        Current total: %u\n", dce2_memory.smb_total);
            _dpd.logMsg("        Maximum total: %u\n", dce2_memory.smb_total_max);
            _dpd.logMsg("        Current session data: %u\n", dce2_memory.smb_ssn);
            _dpd.logMsg("        Maximum session data: %u\n", dce2_memory.smb_ssn_max);
            _dpd.logMsg("        Current segmentation buffering: %u\n", dce2_memory.smb_seg);
            _dpd.logMsg("        Maximum segmentation buffering: %u\n", dce2_memory.smb_seg_max);
            _dpd.logMsg("        Current uid tracking: %u\n", dce2_memory.smb_uid);
            _dpd.logMsg("        Maximum uid tracking: %u\n", dce2_memory.smb_uid_max);
            _dpd.logMsg("        Current tid tracking: %u\n", dce2_memory.smb_tid);
            _dpd.logMsg("        Maximum tid tracking: %u\n", dce2_memory.smb_tid_max);
            _dpd.logMsg("        Current fid tracking: %u\n", dce2_memory.smb_fid);
            _dpd.logMsg("        Maximum fid tracking: %u\n", dce2_memory.smb_fid_max);
            _dpd.logMsg("        Current fid binding tracking: %u\n", dce2_memory.smb_ut);
            _dpd.logMsg("        Maximum fid binding tracking: %u\n", dce2_memory.smb_ut_max);
            _dpd.logMsg("        Current multiplex tracking: %u\n", dce2_memory.smb_pm);
            _dpd.logMsg("        Maximum multiplex tracking: %u\n", dce2_memory.smb_pm_max);
#endif
        }

        if (dce2_stats.tcp_sessions > 0)
        {
            _dpd.logMsg("    TCP\n");
            _dpd.logMsg("      Total sessions: "STDu64"\n", dce2_stats.tcp_sessions);
            _dpd.logMsg("      Packet stats\n");
            _dpd.logMsg("        Packets: "STDu64"\n", dce2_stats.tcp_pkts);
#ifdef DEBUG
            _dpd.logMsg("      Memory stats (bytes)\n");
            _dpd.logMsg("        Current total: %u\n", dce2_memory.tcp_total);
            _dpd.logMsg("        Maximum total: %u\n", dce2_memory.tcp_total_max);
            _dpd.logMsg("        Current session data: %u\n", dce2_memory.tcp_ssn);
            _dpd.logMsg("        Maximum session data: %u\n", dce2_memory.tcp_ssn_max);
#endif
        }

        if (dce2_stats.udp_sessions > 0)
        {
            _dpd.logMsg("    UDP\n");
            _dpd.logMsg("      Total sessions: "STDu64"\n", dce2_stats.udp_sessions);
            _dpd.logMsg("      Packet stats\n");
            _dpd.logMsg("        Packets: "STDu64"\n", dce2_stats.udp_pkts);
#ifdef DEBUG
            _dpd.logMsg("      Memory stats (bytes)\n");
            _dpd.logMsg("        Current total: %u\n", dce2_memory.udp_total);
            _dpd.logMsg("        Maximum total: %u\n", dce2_memory.udp_total_max);
            _dpd.logMsg("        Current session data: %u\n", dce2_memory.udp_ssn);
            _dpd.logMsg("        Maximum session data: %u\n", dce2_memory.udp_ssn_max);
#endif
        }

        if ((dce2_stats.http_server_sessions > 0) || (dce2_stats.http_proxy_sessions > 0))
        {
            _dpd.logMsg("    RPC over HTTP\n");
            if (dce2_stats.http_server_sessions > 0)
                _dpd.logMsg("      Total server sessions: "STDu64"\n", dce2_stats.http_server_sessions);
            if (dce2_stats.http_proxy_sessions > 0)
                _dpd.logMsg("      Total proxy sessions: "STDu64"\n", dce2_stats.http_proxy_sessions);
            _dpd.logMsg("      Packet stats\n");
            if (dce2_stats.http_server_sessions > 0)
                _dpd.logMsg("        Server packets: "STDu64"\n", dce2_stats.http_server_pkts);
            if (dce2_stats.http_proxy_sessions > 0)
                _dpd.logMsg("        Proxy packets: "STDu64"\n", dce2_stats.http_proxy_pkts);
#ifdef DEBUG
            _dpd.logMsg("      Memory stats (bytes)\n");
            _dpd.logMsg("        Current total: %u\n", dce2_memory.http_total);
            _dpd.logMsg("        Maximum total: %u\n", dce2_memory.http_total_max);
            _dpd.logMsg("        Current session data: %u\n", dce2_memory.http_ssn);
            _dpd.logMsg("        Maximum session data: %u\n", dce2_memory.http_ssn_max);
#endif
        }

        if ((dce2_stats.co_pkts > 0) || (dce2_stats.cl_pkts > 0))
        {
            _dpd.logMsg("\n");
            _dpd.logMsg("  DCE/RPC\n");
            if (dce2_stats.co_pkts > 0)
            {
                _dpd.logMsg("    Connection oriented\n");
                _dpd.logMsg("      Packet stats\n");
                _dpd.logMsg("        Packets: "STDu64"\n", dce2_stats.co_pkts);
                if ((dce2_stats.co_bind > 0) || (dce2_stats.co_bind_ack > 0))
                {
                    _dpd.logMsg("        Bind: "STDu64"\n", dce2_stats.co_bind);
                    _dpd.logMsg("        Bind Ack: "STDu64"\n", dce2_stats.co_bind_ack);
                }
                if ((dce2_stats.co_alter_ctx > 0) || (dce2_stats.co_alter_ctx_resp > 0))
                {
                    _dpd.logMsg("        Alter context: "STDu64"\n", dce2_stats.co_alter_ctx);
                    _dpd.logMsg("        Alter context response: "STDu64"\n", dce2_stats.co_alter_ctx_resp);
                }
                if (dce2_stats.co_bind_nack > 0)
                    _dpd.logMsg("        Bind Nack: "STDu64"\n", dce2_stats.co_bind_nack);
                if ((dce2_stats.co_request > 0) || (dce2_stats.co_response > 0))
                {
                    _dpd.logMsg("        Request: "STDu64"\n", dce2_stats.co_request);
                    _dpd.logMsg("        Response: "STDu64"\n", dce2_stats.co_response);
                }
                if (dce2_stats.co_fault > 0)
                    _dpd.logMsg("        Fault: "STDu64"\n", dce2_stats.co_fault);
                if (dce2_stats.co_reject > 0)
                    _dpd.logMsg("        Reject: "STDu64"\n", dce2_stats.co_reject);
                if (dce2_stats.co_auth3 > 0)
                    _dpd.logMsg("        Auth3: "STDu64"\n", dce2_stats.co_auth3);
                if (dce2_stats.co_shutdown > 0)
                    _dpd.logMsg("        Shutdown: "STDu64"\n", dce2_stats.co_shutdown);
                if (dce2_stats.co_cancel > 0)
                    _dpd.logMsg("        Cancel: "STDu64"\n", dce2_stats.co_cancel);
                if (dce2_stats.co_orphaned > 0)
                    _dpd.logMsg("        Orphaned: "STDu64"\n", dce2_stats.co_orphaned);
                if (dce2_stats.co_ms_pdu > 0)
                    _dpd.logMsg("        Microsoft Outlook/Exchange 2003 pdu: "STDu64"\n", dce2_stats.co_ms_pdu);
                if (dce2_stats.co_other_req > 0)
                    _dpd.logMsg("        Other request type: "STDu64"\n", dce2_stats.co_other_req);
                if (dce2_stats.co_other_resp > 0)
                    _dpd.logMsg("        Other response type: "STDu64"\n", dce2_stats.co_other_resp);
                _dpd.logMsg("        Fragments: "STDu64"\n", dce2_stats.co_fragments);
                _dpd.logMsg("        Max fragment size: "STDu64"\n", dce2_stats.co_max_frag_size);
                _dpd.logMsg("        Reassembled: "STDu64"\n", dce2_stats.co_reassembled);
#ifdef DEBUG
                _dpd.logMsg("      Memory stats (bytes)\n");
                _dpd.logMsg("        Current segmentation buffering: %u\n", dce2_memory.co_seg);
                _dpd.logMsg("        Maximum segmentation buffering: %u\n", dce2_memory.co_seg_max);
                _dpd.logMsg("        Current fragment tracker: %u\n", dce2_memory.co_frag);
                _dpd.logMsg("        Maximum fragment tracker: %u\n", dce2_memory.co_frag_max);
                _dpd.logMsg("        Current context tracking: %u\n", dce2_memory.co_ctx);
                _dpd.logMsg("        Maximum context tracking: %u\n", dce2_memory.co_ctx_max);
#endif
            }

            if (dce2_stats.cl_pkts > 0)
            {
                _dpd.logMsg("    Connectionless\n");
                _dpd.logMsg("      Packet stats\n");
                _dpd.logMsg("        Packets: "STDu64"\n", dce2_stats.cl_pkts);
                if ((dce2_stats.cl_request > 0) || (dce2_stats.cl_response > 0))
                {
                    _dpd.logMsg("        Request: "STDu64"\n", dce2_stats.cl_request);
                    _dpd.logMsg("        Response: "STDu64"\n", dce2_stats.cl_response);
                }
                if (dce2_stats.cl_ack > 0)
                    _dpd.logMsg("        Ack: "STDu64"\n", dce2_stats.cl_ack);
                if (dce2_stats.cl_cancel > 0)
                    _dpd.logMsg("        Cancel: "STDu64"\n", dce2_stats.cl_cancel);
                if (dce2_stats.cl_cli_fack > 0)
                    _dpd.logMsg("        Client Fack: "STDu64"\n", dce2_stats.cl_cli_fack);
                if (dce2_stats.cl_ping > 0)
                    _dpd.logMsg("        Ping: "STDu64"\n", dce2_stats.cl_ping);
                if (dce2_stats.cl_reject > 0)
                    _dpd.logMsg("        Reject: "STDu64"\n", dce2_stats.cl_reject);
                if (dce2_stats.cl_cancel_ack > 0)
                    _dpd.logMsg("        Cancel Ack: "STDu64"\n", dce2_stats.cl_cancel_ack);
                if (dce2_stats.cl_srv_fack > 0)
                    _dpd.logMsg("        Server Fack: "STDu64"\n", dce2_stats.cl_srv_fack);
                if (dce2_stats.cl_fault > 0)
                    _dpd.logMsg("        Fault: "STDu64"\n", dce2_stats.cl_fault);
                if (dce2_stats.cl_nocall > 0)
                    _dpd.logMsg("        NoCall: "STDu64"\n", dce2_stats.cl_nocall);
                if (dce2_stats.cl_working > 0)
                    _dpd.logMsg("        Working: "STDu64"\n", dce2_stats.cl_working);
                if (dce2_stats.cl_other_req > 0)
                    _dpd.logMsg("        Other request type: "STDu64"\n", dce2_stats.cl_other_req);
                if (dce2_stats.cl_other_resp > 0)
                    _dpd.logMsg("        Other response type: "STDu64"\n", dce2_stats.cl_other_resp);
                _dpd.logMsg("        Fragments: "STDu64"\n", dce2_stats.cl_fragments);
                _dpd.logMsg("        Max fragment size: "STDu64"\n", dce2_stats.cl_max_frag_size);
                _dpd.logMsg("        Reassembled: "STDu64"\n", dce2_stats.cl_reassembled);
                if (dce2_stats.cl_max_seqnum > 0)
                    _dpd.logMsg("        Max seq num: "STDu64"\n", dce2_stats.cl_max_seqnum);
#ifdef DEBUG
                _dpd.logMsg("      Memory stats (bytes)\n");
                _dpd.logMsg("        Current activity tracker: %u\n", dce2_memory.cl_act);
                _dpd.logMsg("        Maximum activity tracker: %u\n", dce2_memory.cl_act_max);
                _dpd.logMsg("        Current fragment tracker: %u\n", dce2_memory.cl_frag);
                _dpd.logMsg("        Maximum fragment tracker: %u\n", dce2_memory.cl_frag_max);
#endif
            }
        }
    }

    /* Have to free it here because CleanExit is called before stats functions
     * (so anything flushed by stream can go through and count towards stats) */
    if (exiting)
        DCE2_StatsFree();

#ifdef DEBUG
    _dpd.logMsg("\n");
    _dpd.logMsg("  Memory stats (bytes)\n");
    _dpd.logMsg("    Current total: %u\n", dce2_memory.total);
    _dpd.logMsg("    Maximum total: %u\n", dce2_memory.total_max);
    _dpd.logMsg("    Current runtime total: %u\n", dce2_memory.rtotal);
    _dpd.logMsg("    Maximum runtime total: %u\n", dce2_memory.rtotal_max);
    _dpd.logMsg("    Current config total: %u\n", dce2_memory.config);
    _dpd.logMsg("    Maximum config total: %u\n", dce2_memory.config_max);
    _dpd.logMsg("    Current rule options total: %u\n", dce2_memory.roptions);
    _dpd.logMsg("    Maximum rule options total: %u\n", dce2_memory.roptions_max);
    _dpd.logMsg("    Current routing table total: %u\n", dce2_memory.rt);
    _dpd.logMsg("    Maximum routing table total: %u\n", dce2_memory.rt_max);
    _dpd.logMsg("    Current initialization total: %u\n", dce2_memory.init);
    _dpd.logMsg("    Maximum initialization total: %u\n", dce2_memory.init_max);
#endif
}

/******************************************************************
 * Function: DCE2_Reset()
 *
 * Purpose: Reset the preprocessor to a post configuration state.
 *
 * Arguments:
 *  int - signal that caused the reset
 *  void * - pointer to data
 *       
 * Returns: None
 *
 ******************************************************************/ 
static void DCE2_Reset(int signal, void *data)
{
    if (!DCE2_CStackIsEmpty(dce2_pkt_stack))
    {
        DCE2_Log(DCE2_LOG_TYPE__ERROR,
                 "%s(%d) Packet stack is not empty when it should be.",
                 __FILE__, __LINE__);

        DCE2_CStackEmpty(dce2_pkt_stack);
    }
}

/******************************************************************
 * Function: DCE2_ResetStats()
 *
 * Purpose: Reset any statistics being kept by the preprocessor.
 *
 * Arguments:
 *  int - signal that caused function to be called
 *  void * - pointer to data
 *       
 * Returns: None
 *
 ******************************************************************/ 
static void DCE2_ResetStats(int signal, void *data)
{
    DCE2_StatsInit();
}

/******************************************************************
 * Function: DCE2_CleanExit()
 *
 * Purpose: Do any cleanup necessary when Snort exits.
 *
 * Arguments:
 *  int - signal that caused Snort to exit
 *  void * - pointer to data
 *       
 * Returns: None
 *
 ******************************************************************/ 
static void DCE2_CleanExit(int signal, void *data)
{    
    DCE2_FreeGlobals();
}


