/*
 * The wireshark-lttng-plugin -- a dissector for LTTng Live protocols
 * Copyright (C) 2017 Itiviti AB
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * LTTng is an open source software developed by EfficiOS Inc.
 * http://lttng.org/
 * http://www.efficios.com/about-efficios
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 */

/*
 * moduleinfo.c
 * Module info definition for Wireshark plugin
 */
#include <gmodule.h>       /* Glib */
#include <config.h>        /* Wireshark's config header */
#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */

#define WS_BUILD_DLL
#include <ws_symbol_export.h>

#include "moduleinfo.h"
#include "packet-lttng_control.h"
#include "packet-lttng_data.h"
#include "packet-lttng_live.h"

/* Symbols for Wireshark */
WS_DLL_PUBLIC_DEF gchar version[30] = LTTNG_MODULE_VERSION;

WS_DLL_PUBLIC_DEF void plugin_register(void);
WS_DLL_PUBLIC_DEF void plugin_reg_handoff(void);

WS_DLL_PUBLIC_DEF void plugin_register(void)
{
    lttng_control_proto_register();
    lttng_data_proto_register();
    lttng_live_proto_register();
}

WS_DLL_PUBLIC_DEF void plugin_reg_handoff(void)
{
    lttng_control_proto_reg_handoff();
    lttng_data_proto_reg_handoff();
    lttng_live_proto_reg_handoff();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
