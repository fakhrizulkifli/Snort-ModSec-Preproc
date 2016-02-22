/*
 * vim:sw=4 ts=4:et sta
 *
 *
 * Copyright (c) 2016, Fakhri Zulkifli <mohdfakhrizulkifli at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of spp_modsecurity nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "snort_debug.h"
#include "preprocids.h"
#include "spp_modsecurity.h"
#include "sf_preproc_info.h"

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats modsecurityPerfStats;
#endif

/* const int MAJOR_VERSION = 0; */
/* const int MINOR_VERSION = 1; */
/* const int BUILD_VERSION = 1; */
/* const char *PREPROC_NAME = "SF_MODSECURITY"; */

#define SetupModsecurity DYNAMIC_PREPROC_SETUP

/* Preprocessor config objects */
static tSfPolicyUserContextId modsecurity_context_id = NULL;
//static modsecurity_config_t *modsecurity_eval_config = NULL;

/* Target-based app ID */
#ifdef TARGET_BASED
int16_t modsecurity_app_id = SFTARGET_UNKNOWN_PROTOCOL;
#endif

/* Func Prototypes */
static void ModsecurityInit(struct _SnortConfig *, char *);
static void ModsecurityProcess(void *, void *);
static modsecurity_config_t *ModsecurityParse(char *);

#ifdef SNORT_RELOAD
static void ModsecurityReload(struct _SnortConfig *, char *, void **);
static int ModsecurityReloadVerify(struct _SnortConfig *, void *);
static void *ModsecurityReloadSwap(struct _SnortConfig *, void *);
static void ModsecurityReloadSwapFree(void *);
#endif

void ModsecuritySetup(void)
{
#ifndef SNORT_RELOAD
    _dpd.registerPreproc("modsecurity", ModsecurityInit);
#else
    _dpd.registerPreproc("modsecurity", ModsecurityInit, ModsecurityReload,
            ModsecurityReloadVerify, ModsecurityReloadSwap, ModsecurityReloadSwapFree);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: Modsecurity is setup\n"););
}

static void ModsecurityInit(struct _SnortConfig *sc, char *args)
{
    modsecurity_config_t *config;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);

    _dpd.logMsg("Modsecurity preprocessor configuration\n");

    if (modsecurity_context_id == NULL)
    {
        modsecurity_context_id = sfPolicyConfigCreate();
        if (modsecurity_context_id == NULL)
            _dpd.fatalMsg("Could not allocate configuration struct.\n");
    }

    config = ModsecurityParse(args);
    sfPolicyUserPolicySet(modsecurity_context_id, policy_id);
    sfPolicyUserDataSetCurrent(modsecurity_context_id, config);

    _dpd.addPreproc(sc, ModsecurityProcess, PRIORITY_TRANSPORT, 0, PROTO_BIT__TCP | PROTO_BIT__UDP);
#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("modsecurity", (void *) &modsecurityPerfStats, 0, _dpd.totalPerfStats, NULL);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: Modsecurity is initialized\n"));
}

static modsecurity_config_t *ModsecurityParse(char *args)
{
    char *arg;
    //char *argEnd;
    uint8_t port = 0;
    modsecurity_config_t *config = (modsecurity_config_t *) calloc(1, sizeof(modsecurity_config_t));

    if (config == NULL)
        _dpd.fatalMsg("Could not allocate configuration struct.\n");

    arg = strtok(args, "\t\n\r");
    if (arg && !strcasecmp("port", arg))
    {
        arg = strtok(NULL, "\t\n\r");
        if (!arg)
        {
            _dpd.fatalMsg("Modsecurity: Missing port\n");
        }

        config->ports = (uint8_t) port;

        _dpd.logMsg("   Port: %d\n", config->ports);
    }
    else
    {
        _dpd.fatalMsg("Modsecurity: Invalid option %s\n", arg ? arg : "(missing port)");
    }

    return config;
}

static void ModsecurityProcess(void *pkt, void *context)
{
    SFSnortPacket *packet = (SFSnortPacket *) pkt;
    modsecurity_config_t *config;
    PROFILE_VARS;

    sfPolicyUserPolicySet(modsecurity_context_id, _dpd.getNapRuntimePolicy());
    config = (modsecurity_config_t *) sfPolicyUserDataGetCurrent(modsecurity_context_id);

    if (config == NULL)
        return;

    PREPROC_PROFILE_START(modsecurityPerfStats);

    if (packet->src_port == config->ports)
    {
        /* Check source port */
        DynamicPreprocessorFatalMessage("Modsecurity Src Port Found: %d\n", packet->src_port);

        PREPROC_PROFILE_END(modsecurityPerfStats);
        return;
    }

    if (packet->dst_port == config->ports)
    {
        DynamicPreprocessorFatalMessage("Modsecurity Dst Port Found: %d\n", packet->dst_port);

        PREPROC_PROFILE_END(modsecurityPerfStats);
        return;
    }

    PREPROC_PROFILE_END(modsecurityPerfStats);
}

#ifdef SNORT_RELOAD
static void ModsecurityReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    tSfPolicyUserContextId modsecurity_swap_config = (tSfPolicyUserContextId) *new_config;
    modsecurity_config_t *config;
    tSfPolicyId policy_id = _dpd.getParserPolicy(sc);

    _dpd.logMsg("Modsecurity dynamic preprocessor configuration\n");

    modsecurity_swap_config = sfPolicyConfigCreate();

    if (modsecurity_swap_config == NULL)
        _dpd.fatalMsg("Could not allocate configuration struct\n");

    config = ModsecurityParse(args);
    sfPolicyUserPolicySet(modsecurity_swap_config, policy_id);
    sfPolicyUserDataSetCurrent(modsecurity_swap_config, config);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Preprocessor: Modsecurity is initialized\n"););
}

static int ModsecurityReloadVerify(struct _SnortConfig *sc, void *swap_config)
{
    if (!_dpd.isPreprocEnabled(sc, PP_STREAM))
    {
        _dpd.errMsg("Streaming & reassembly must be enabled for example preprocessor\n");
        return MODSECURITY_FAILURE;
    }

    return MODSECURITY_SUCCESS;
}

static void *ModsecurityReloadSwap(struct _SnortConfig *sc, void *swap_config)
{
    tSfPolicyUserContextId modsecurity_context_swap_config = (tSfPolicyUserContextId) swap_config;
    tSfPolicyUserContextId old_config = modsecurity_context_id;

    if (modsecurity_context_swap_config == NULL) return NULL;

    modsecurity_context_id = modsecurity_context_swap_config;

    return (void *) old_config;
}

static void ModsecurityReloadSwapFree(void *data)
{
    tSfPolicyUserContextId config = (tSfPolicyUserContextId) data;

    if (data == NULL) return;

    //sfPolicyUserDataFreeIterate(config, ModsecurityReloadSwap);
    sfPolicyConfigDelete(config);
}
#endif
