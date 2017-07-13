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
 * lttng_live-fields.inc
 * X-macro declaration for LTTng Live protocol fields
 *
 * LTTng Live protocol is defined in
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/doc/live-reading-protocol.txt
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/src/bin/lttng-relayd/lttng-viewer-abi.h
 */

#ifndef FIELD
#error "You are not using this file properly!"
#endif

FIELD(cmd_data_size, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Data Size")
FIELD(cmd_id, uint32_t, FT_UINT32, BASE_DEC, VALS(cmd_id_vals),
    "Command")
FIELD(cmd_version, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Command Version")
FIELD(session_id, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Session Id")
FIELD(protocol_version_major, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Protocol Version Major")
FIELD(protocol_version_minor, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Protocol Version Minor")
FIELD(connection_type, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Connection Type")
FIELD(sessions_count, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Sessions Count")
FIELD(session_attach_status,  uint32_t, FT_UINT32, BASE_DEC, VALS(session_attach_status_vals),
    "Session Attach Status")
FIELD(session_create_status,  uint32_t, FT_UINT32, BASE_DEC, VALS(session_create_status_vals),
    "Session Create Status")
FIELD(metadata_status,  uint32_t, FT_UINT32, BASE_DEC, VALS(metadata_status_vals),
    "Metadata Status")
FIELD(packet_status,  uint32_t, FT_UINT32, BASE_DEC, VALS(packet_status_vals),
    "Packet Status")
FIELD(index_status,  uint32_t, FT_UINT32, BASE_DEC, VALS(index_status_vals),
    "Index Status")
FIELD(new_streams_status,  uint32_t, FT_UINT32, BASE_DEC, VALS(new_streams_status_vals),
    "New Streams Status")
FIELD(streams_count, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Streams Count")
FIELD(viewer_offset, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Offset")
FIELD(viewer_seek, uint32_t, FT_UINT32, BASE_DEC, VALS(viewer_seek_vals),
    "Seek")
FIELD(packet_size, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Packet Size (bits)")
FIELD(content_size, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Content Size (bits)")
FIELD(timestamp_begin, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Timestamp Begin")
FIELD(timestamp_end, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Timestamp End")
FIELD(events_discarded, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Events Discarded")
FIELD(stream_id, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Stream Id")
FIELD(stream_offset, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Stream Offset")
FIELD(flags, uint32_t, FT_UINT32, BASE_HEX, NULL,
    "Flags")
FIELD(packet_flags, uint32_t, FT_UINT32, BASE_HEX, NULL,
    "Packet Flags")
FIELD(index_flags, uint32_t, FT_UINT32, BASE_HEX, NULL,
    "Index Flags")
FIELD(packet_length, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Packet Length")
FIELD(metadata_length, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Metadata Length")
FIELD(live_timer, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Live Timer")
FIELD(num_clients, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Clients Number")
FIELD(num_streams, uint32_t, FT_UINT32, BASE_DEC, NULL,
    "Streams Number")
FIELD(hostname_str, string64_t, FT_STRING, BASE_NONE, NULL,
    "Hostname")
FIELD(session_name_str, string255_t, FT_STRING, BASE_NONE, NULL,
    "Session Name")
FIELD(ctf_trace_id, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "CTF Trace Id")
FIELD(metadata_flag, uint32_t, FT_UINT32, BASE_HEX, NULL,
    "Metadata Flag")
FIELD(path_name, string4096_t, FT_STRING, BASE_NONE, NULL,
    "Path Name")
FIELD(channel_name, string255_t, FT_STRING, BASE_NONE, NULL,
    "Channel Name")
FIELD(session_struct, int, FT_BYTES, BASE_NONE, NULL,
    "Session Struct")
FIELD(stream_struct, int, FT_BYTES, BASE_NONE, NULL,
    "Stream Struct")

/* Generated fields */
FIELD(request_frame_number, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Request Frame Number")
FIELD(message_type, uint32_t, FT_UINT32, BASE_DEC, VALS(message_type_vals),
    "Message Type")
FIELD(packet_size_bytes, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Packet Size (bytes)")
FIELD(content_size_bytes, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Content Size (bytes)")
FIELD(request_stream_id, uint64_t, FT_UINT64, BASE_DEC, NULL,
    "Request Stream Id")


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
