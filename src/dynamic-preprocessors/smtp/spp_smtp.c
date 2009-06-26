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
 
/**************************************************************************
 *
 * spp_smtp.c
 *
 * Author: Andy Mullican
 *
 * Description:
 *
 * This file initializes SMTP as a Snort preprocessor.
 *
 * This file registers the SMTP initialization function,
 * adds the SMTP function into the preprocessor list.
 *
 * In general, this file is a wrapper to SMTP functionality,
 * by interfacing with the Snort preprocessor functions.  The rest
 * of SMTP should be separate from the preprocessor hooks.
 *
 **************************************************************************/

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "spp_smtp.h"
#include "snort_smtp.h"
#include "smtp_config.h"
#include "smtp_log.h"

#include "preprocids.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "debug.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats smtpPerfStats;
PreprocStats smtpDetectPerfStats;
int smtpDetectCalled = 0;
#endif

#include "sf_types.h"

extern DynamicPreprocessorData _dpd;
extern SMTP _smtp_no_session;
extern int _smtp_check_gaps;
extern int16_t _smtp_proto_id;
extern SMTPConfig     _smtp_config;

static void SMTPInit(char *);
static void SMTP_XLINK_Init(char *);
static void SMTPDetect(void *, void *context);
static void SMTPCleanExitFunction(int, void *);
static void SMTPRestartFunction(int, void *);
static void SMTPResetFunction(int, void *);
static void SMTPResetStatsFunction(int, void *);
static void _addPortsToStream5Filter();
#ifdef TARGET_BASED
static void _addServicesToStream5Filter();
#endif


/*
 * Function: SetupSMTP()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  This is the function that
 *          gets called from InitPreprocessors() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupSMTP(void)
{
    /* link the preprocessor keyword to the init function in the preproc list */
    _dpd.registerPreproc("smtp", SMTPInit);
    _dpd.registerPreproc("xlink2state", SMTP_XLINK_Init);
}


/*
 * Function: SMTPInit(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void SMTPInit(char *args)
{
    static int config_done = 0;

    if (config_done)
    {
        DynamicPreprocessorFatalMessage("Can only configure SMTP preprocessor once.\n");
    }

    if (!_dpd.streamAPI)
    {
        DynamicPreprocessorFatalMessage("Streaming & reassembly must be enabled "
                                        "for SMTP preprocessor\n");
    }

#ifdef TARGET_BASED
    _smtp_proto_id = _dpd.findProtocolReference(SMTP_PROTO_REF_STR);
    if (_smtp_proto_id == SFTARGET_UNKNOWN_PROTOCOL)
        _smtp_proto_id = _dpd.addProtocolReference(SMTP_PROTO_REF_STR);

    DEBUG_WRAP(DebugMessage(DEBUG_SMTP,"SMTP: Target-based: Proto id for %s: %u.\n",
                            SMTP_PROTO_REF_STR, _smtp_proto_id););
#endif

    if (_dpd.streamAPI->version >= STREAM_API_VERSION5)
        _smtp_check_gaps = 1;
    else
        _smtp_check_gaps = 0;

    SMTP_InitCmds();

    SMTP_ParseArgs(args);

    /* initialize the searches - command, headers, data, etc. */
    SMTP_SearchInit();

    /* zero out static SMTP global used for stateless SMTP or if there
     * is no session pointer */
    memset(&_smtp_no_session, 0, sizeof(SMTP));

    /* Put the preprocessor function into the function list */
    _dpd.addPreproc(SMTPDetect, PRIORITY_APPLICATION, PP_SMTP, PROTO_BIT__TCP);
    _dpd.addPreprocExit(SMTPCleanExitFunction, NULL, PRIORITY_LAST, PP_SMTP);
    _dpd.addPreprocRestart(SMTPRestartFunction, NULL, PRIORITY_LAST, PP_SMTP);
    _dpd.addPreprocReset(SMTPResetFunction, NULL, PRIORITY_LAST, PP_SMTP);
    _dpd.addPreprocResetStats(SMTPResetStatsFunction, NULL, PRIORITY_LAST, PP_SMTP);

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("smtp", (void*)&smtpPerfStats, 0, _dpd.totalPerfStats);        
#endif

    config_done = 1;

    _addPortsToStream5Filter();
#ifdef TARGET_BASED
    _addServicesToStream5Filter();
#endif
}


/*
 * Function: SMTP_XLINK_Init(char *)
 *
 * Purpose: Dummy function to make upgrade easier.  If preprocessor
 *           xlink2state is configured in snort.conf, just ignore it.
  *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void SMTP_XLINK_Init(char *args)
{
    return;
}


/*
 * Function: SMTPDetect(void *, void *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
static void SMTPDetect(void *pkt, void *context)
{
    SFSnortPacket *p = (SFSnortPacket *)pkt;
    PROFILE_VARS;

    if ((p->payload_size == 0) || !IsTCP(p) || (p->payload == NULL))
        return;

    PREPROC_PROFILE_START(smtpPerfStats);

    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "SMTP Start (((((((((((((((((((((((((((((((((((((((\n"););

    SnortSMTP(p);

    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "SMTP End )))))))))))))))))))))))))))))))))))))))))\n\n"););

    PREPROC_PROFILE_END(smtpPerfStats);
#ifdef PERF_PROFILING
    if (PROFILING_PREPROCS && smtpDetectCalled)
    {
        smtpPerfStats.ticks -= smtpDetectPerfStats.ticks;
        /* And Reset ticks to 0 */
        smtpDetectPerfStats.ticks = 0;
        smtpDetectCalled = 0;
    }
#endif

}


/* 
 * Function: SMTPCleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting, if there's
 *          any cleanup that needs to be performed (e.g. closing files)
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    function when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void SMTPCleanExitFunction(int signal, void *data)
{    
    SMTP_Free();
}


/* 
 * Function: SMTPRestartFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is restarting on a SIGHUP,
 *          if there's any initialization or cleanup that needs to happen
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    functioin when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void SMTPRestartFunction(int signal, void *foo)
{
    return;
}

static void SMTPResetFunction(int signal, void *data)
{
    return;
}

static void SMTPResetStatsFunction(int signal, void *data)
{
    return;
}

static void _addPortsToStream5Filter()
{
    unsigned int portNum;

    for (portNum = 0; portNum < MAXPORTS; portNum++)
    {
        if(_smtp_config.ports[(portNum/8)] & (1<<(portNum%8)))
        {
            //Add port the port
            _dpd.streamAPI->set_port_filter_status(IPPROTO_TCP, (u_int16_t)portNum, PORT_MONITOR_SESSION);
        }
    }
}
#ifdef TARGET_BASED
static void _addServicesToStream5Filter()
{
    _dpd.streamAPI->set_service_filter_status(_smtp_proto_id, PORT_MONITOR_SESSION);
}
#endif

