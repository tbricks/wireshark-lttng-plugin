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
 * lttng_control-fields.inc
 * X-macro declaration for LTTng Control protocol fields
 *
 * LTTng Control protocol is defined in
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/src/common/sessiond-comm/relayd.h
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/src/common/sessiond-comm/sessiond-comm.h
 */

#ifndef FIELD
#error "You are not using this file properly!"
#endif

FIELD(circuit_id, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Circuit Id")
FIELD(cmd_data_size, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Data Size")
FIELD(cmd_id, uint32_t, FT_UINT32, BASE_DEC, VALS(cmd_id_vals),
    "Command")
FIELD(cmd_version, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Command Version")
FIELD(channel_name, channel_name_t, FT_STRING, BASE_NONE, NULL,
    "Channel Name")
FIELD(path_name, path_name_t, FT_STRING, BASE_NONE, NULL,
    "Path Name")
FIELD(tracefile_size, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Trace File Size")
FIELD(tracefile_count, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Trace File Count")
FIELD(handle, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Handle")
FIELD(return_code, uint32_t, FT_UINT32, BASE_DEC, VALS(return_code_vals),
    "Return Code")
FIELD(stream_id, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Stream Id")
FIELD(padding_size, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Padding Size")
FIELD(relay_stream_id, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Relay Stream Id")
FIELD(net_seq_num, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Net Seq Num")
FIELD(packet_size, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Packet Size")
FIELD(content_size, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Content Size")
FIELD(timestamp_begin, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Timestamp Begin")
FIELD(timestamp_end, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Timestamp End")
FIELD(events_discarded, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Events Discarded")


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
