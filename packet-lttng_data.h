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
 * packet-lttng_data.h
 * Routines for LTTng Data protocol dissection
 *
 * LTTng Data protocol is defined in
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/src/common/sessiond-comm/relayd.h
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/src/common/sessiond-comm/sessiond-comm.h
 */
#ifndef WS_LTTNG_PACKET_LTTNG_DATA_H
#define WS_LTTNG_PACKET_LTTNG_DATA_H

#include <gmodule.h>       /* Glib */
#include <config.h>        /* Wireshark's config header */
#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */

extern void lttng_data_proto_reg_handoff(void);
extern void lttng_data_proto_register(void);
extern int lttng_data_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

#endif /* WS_LTTNG_PACKET_LTTNG_DATA_H */

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
