/*
 * Copyright (c) 2011 Alexandria Wolcott
 * Rights to this code are documented in doc/LICENSE.
 *
 * This file contains functionality for alerting on large connections.
 *
 */

#include "atheme.h"
#include "conf.h"
#include <limits.h>

static void connavg_newuser(hook_user_nick_t *data);
static void connavg_configready(void *unused);
static void os_cmd_connavg(sourceinfo_t *si, int parc, char *parv[]);

typedef struct
{
    int connections;
    int peak_time;
    int peak_conn;
    int alert_time;
    int check_time;
} state;

state s;

unsigned int safe_connections = 0;

DECLARE_MODULE_V1
(
 "operserv/connavg",  false,  _modinit,  _moddeinit,
 PACKAGE_STRING,
 "Alexandria Wolcott <alyx@sporksmoo.net>"
 );

command_t os_connavg = { "CONNAVG", N_("Monitors the network for unusual connection fluxuations."), PRIV_SERVER_AUSPEX, 1, os_cmd_connavg, { .path = "oservice/connavg" } };

static void reset_connections(void *unused)
{
    s.connections = 0;
    s.check_time = time(NULL);
}

void _modinit(module_t *m)
{
    service_named_bind_command("operserv", &os_connavg);
    hook_add_event("user_add");
    hook_add_user_add(connavg_newuser);
    add_uint_conf_item("SAFE_CONNECTIONS", &conf_gi_table, 0, &safe_connections, 1, INT_MAX, 5);
    event_add("reset_connections", reset_connections, NULL, 60);
}

void _moddeinit(module_unload_intent_t intent)
{
    service_named_unbind_command("operserv", &os_connavg);
    hook_del_user_add(connavg_newuser);
    hook_del_event("user_add");
    del_conf_item("SAFE_CONNECTIONS", &conf_gi_table);
    event_delete(reset_connections, NULL);
}

static void os_cmd_connavg(sourceinfo_t *si, int parc, char *parv[])
{
    command_success_nodata(si, _("Connections in the last minute: %d"), s.connections);
    
    if (s.peak_time != 0)
        command_success_nodata(si, _("Peak connections: %d (Reached %s ago)"), s.peak_conn, time_ago(s.peak_time));
    command_success_nodata(si, _("Configuration alert level: %d"), safe_connections);
    
    if (s.alert_time != 0)
        command_success_nodata(si, _("Alert peak last broken: %s ago"), time_ago(s.alert_time));
    else
        command_success_nodata(si, _("Alert peak last broken: never"));
    
    logcommand(si, CMDLOG_GET, "CONNAVG");
}

static void connavg_newuser(hook_user_nick_t *data)
{
    user_t *u = data->u;

    /* If the user has been killed, don't do anything. */
    if (!(u))
        return;

    /* If the user is an internal client, still don't do anything. */
    if (is_internal_client(u))
        return;

    /* Most likely, we will have a massive influx in connections when bursts happen; skip those. */
    if (me.bursting)
        return;

    s.connections++;

    if (s.connections > safe_connections)
    {
        /* Send a warning every five connects greater than the "safe" connection allowence. */
        if (s.connections % 5 == 0) {
            wallops("WARNING! Connections in the last minute was %d, which is above the maxium safe connections of %d per minute!",
                    s.connections, safe_connections);
            s.alert_time = time(NULL);
        }
    }

    if (s.connections > s.peak_conn)
    {
        s.peak_conn = s.connections;
        s.peak_time = time(NULL);
    }
}

/* vim:cinoptions=>s,e0,n0,f0,{0,}0,^0,=s,ps,t0,c3,+s,(2s,us,)20,*30,gs,hs
 * vim:ts=8
 * vim:sw=8
 * vim:noexpandtab
 */
