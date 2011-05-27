/*
 * Copyright (c) 2011 Alexandria Wolcott
 * Rights to this code are documented in doc/LICENSE.
 *
 * This file contains functionality for alerting on large connections.
 *
 */

#include "atheme.h"

static void connavg_newuser(hook_user_nick_t *data);
static void connavg_configready(void *unused);
static void os_cmd_connavg(sourceinfo_t *si, int parc, char *parv[]);

#define MAXCONNS 20

typedef struct
{
    int connections;
    int peak_time;
    int peak_conn;
    int alert_time;
    int check_time;
} state;

state s;

DECLARE_MODULE_V1
(
 "operserv/connavg",  false,  _modinit,  _moddeinit,
 PACKAGE_STRING,
 "Alexandria Wolcott <alyx@sporksmoo.net>"
 );

command_t os_connavg = { "CONNAVG", N_("Monitors the network for unusual connection fluxuations."), PRIV_SERVER_AUSPEX, 1, os_cmd_connavg, { .path = "oservice/connavg" } };

void _modinit(module_t *m)
{
    service_named_bind_command("operserv", &os_connavg);
    hook_add_event("user_add");
    hook_add_user_add(connavg_newuser);
}

void _moddeinit(module_unload_intent_t intent)
{
    service_named_unbind_command("operserv", &os_connavg);
    hook_del_user_add(connavg_newuser);
    hook_del_event("user_add");
}

static void os_cmd_connavg(sourceinfo_t *si, int parc, char *parv[])
{
    if (time(NULL) > (s.check_time + 60)) {
        s.connections = 0;
        s.check_time = time(NULL);
    }
    command_success_nodata(si, _("Connections in the last minute: %d"), s.connections);
    /*command_success_nodata(si, _("Peak connections: %d (last connection was %s ago)"), s.peak_conn, (temp != NULL ? temp : "N/A"));*/
    if (s.peak_time != 0)
        command_success_nodata(si, _("Peak connections: %d (Reached %s ago)"), s.peak_conn, time_ago(s.peak_time));
    command_success_nodata(si, _("Configuration alert level: %d"), MAXCONNS);
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

    if (s.connections > MAXCONNS)
    {
        if (s.connections % 5 == 0) {
            wallops("WARNING! Connections in the last minute was %d, which is above the maxium safe connections of %d per minute!",
                    s.connections, MAXCONNS);
            s.alert_time = time(NULL);
        }
    }

    if (s.connections > s.peak_conn)
    {
        s.peak_conn = s.connections;
        s.peak_time = time(NULL);
    }

    if (time(NULL) > (s.check_time + 60))
    {
        s.connections = 0;
        s.check_time = time(NULL);
    }
}

/* vim:cinoptions=>s,e0,n0,f0,{0,}0,^0,=s,ps,t0,c3,+s,(2s,us,)20,*30,gs,hs
 * vim:ts=8
 * vim:sw=8
 * vim:noexpandtab
 */
