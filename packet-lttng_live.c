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
 * packet-lttng_live.c
 * Routines for LTTng Live protocol dissection
 *
 * LTTng Live protocol is defined in
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/doc/live-reading-protocol.txt
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/src/bin/lttng-relayd/lttng-viewer-abi.h
 */
#include <stdint.h>
#include <assert.h>
#include <gmodule.h>       /* Glib */
#include <config.h>        /* Wireshark's config header */
#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/dissectors/packet-tcp.h>
#include <epan/conversation.h>
#include <epan/packet_info.h>

#include "moduleinfo.h"
#include "packet-lttng_common.h"
#include "packet-lttng_live.h"

typedef char string64_t[64];
typedef char string255_t[255];
typedef char string4096_t[4096];

#define LTTNG_LIVE_TCP_PORT 5344
#define LTTNG_LIVE_MODULE_NAME         LTTNG_MODULE_NAME "_Live"
#define LTTNG_LIVE_MODULE_SHORT_NAME   LTTNG_MODULE_SHORT_NAME "_Live"
#define LTTNG_LIVE_MODULE_FILTER_NAME  LTTNG_MODULE_FILTER_NAME "_live"

static int lttng_live_proto = -1;
static int lttng_live_header_ett = -1;
static int lttng_live_content_ett = -1;

static int lttng_hf[] = {
    #define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) -1,
        #include "fields-lttng_live.h"
    #undef FIELD
};

typedef enum lttng_live_field {
    #define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) FIELD_##name,
        #include "fields-lttng_live.h"
    #undef FIELD
} lttng_live_field_t;

#define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) typedef type TYPE_##name;
    #include "fields-lttng_live.h"
#undef FIELD

enum lttng_live_cmd_id {
    CMD_ID_CONNECT = 1,
    CMD_ID_LIST_SESSIONS = 2,
    CMD_ID_ATTACH_SESSION = 3,
    CMD_ID_GET_NEXT_INDEX = 4,
    CMD_ID_GET_PACKET = 5,
    CMD_ID_GET_METADATA = 6,
    CMD_ID_GET_NEW_STREAMS = 7,
    CMD_ID_CREATE_SESSION = 8,
};

static const value_string cmd_id_vals[] = {
    { CMD_ID_CONNECT, "Connect" },
    { CMD_ID_LIST_SESSIONS, "List Sessions" },
    { CMD_ID_ATTACH_SESSION, "Attach Session" },
    { CMD_ID_GET_NEXT_INDEX, "Get Next Index" },
    { CMD_ID_GET_PACKET, "Get Packet" },
    { CMD_ID_GET_METADATA, "Get Metadata" },
    { CMD_ID_GET_NEW_STREAMS, "Get New Streams" },
    { CMD_ID_CREATE_SESSION, "Create Session" },
    { 0, NULL},
};

static const value_string session_attach_status_vals[] = {
    { 1, "OK" },
    { 2, "Already" },
    { 3, "Unknown" },
    { 4, "Not Live" },
    { 5, "Seek Error" },
    { 6, "No Session" },
    { 0, NULL },
};

static const value_string session_create_status_vals[] = {
    { 1, "OK" },
    { 2, "Error" },
    { 0, NULL },
};

static const value_string metadata_status_vals[] = {
    { 1, "OK" },
    { 2, "No New Metadata" },
    { 3, "Error" },
    { 0, NULL },
};

static const value_string packet_status_vals[] = {
    { 1, "OK" },
    { 2, "Retry" },
    { 3, "Error" },
    { 4, "EOF" },
    { 0, NULL },
};

static const value_string index_status_vals[] = {
    { 1, "OK" },
    { 2, "Retry" },
    { 3, "Closed" },
    { 4, "Error" },
    { 5, "Inactive" },
    { 6, "EOF" },
    { 0, NULL },
};

static const value_string new_streams_status_vals[] = {
    { 1, "OK" },
    { 2, "No New Streams Available" },
    { 3, "Error" },
    { 4, "Session Closed" },
    { 0, NULL },
};

static const value_string viewer_seek_vals[] = {
    { 1, "Seek Beginning" },
    { 2, "Seek Last" },
    { 0, NULL },
};

enum lttng_live_message_type {
    MESSAGE_TYPE_REQUEST = 1,
    MESSAGE_TYPE_REPLY = 2,
};

static const value_string message_type_vals[] = {
    { MESSAGE_TYPE_REQUEST, "Request" },
    { MESSAGE_TYPE_REPLY, "Reply" },
    { 0, NULL },
};

typedef struct lttng_live_frame_annotation {
    unsigned int is_client:1;
    unsigned int cmd_id:4; /* currently we have only 8 commands */
    uint64_t stream_id;
} lttng_live_frame_annotation_t;

#define MAX_NUM_FRAMES 1000000
static lttng_live_frame_annotation_t frames[MAX_NUM_FRAMES];

static lttng_live_frame_annotation_t *
get_frame_ref(uint64_t current_frame) {
    if (current_frame < MAX_NUM_FRAMES) {
        return & frames[current_frame];
    } else {
        return NULL;
    }
}

static lttng_live_frame_annotation_t *
find_client_request(uint64_t current_frame, uint64_t *request_frame) {
    lttng_live_frame_annotation_t *result = NULL;
    if(current_frame < MAX_NUM_FRAMES) {
        for (size_t i = current_frame - 1; i > 0; i--) {
            if(frames[i].is_client) {
                result = & frames[i];
                if (request_frame != NULL) {
                    *request_frame = i;
                }
                break;
            }
        }
    }
    return result;
}

static guint
get_lttng_live_pdu_len_client(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint pdu_offset = 0;
    ADVANCE_FIELD_ASSIGN(cmd_data_size);
    ADVANCE_FIELD(cmd_id);
    ADVANCE_FIELD(cmd_version);
    ADVANCE_LENGTH(cmd_data_size);
    return pdu_offset;
}

static int
dissect_lttng_live_pdu_client(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    lttng_live_frame_annotation_t * const request = get_frame_ref(pinfo->fd->num);
    if(request == NULL) {
        // TODO complain somehow
        return 0;
    }

    guint offset = 0;
    guint pdu_offset = 0;

    proto_item *item = proto_tree_add_item(tree, lttng_live_proto, tvb, 0, -1, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(item, lttng_live_header_ett);

    proto_item * message_type_item = proto_tree_add_uint(subtree,
        lttng_hf[FIELD_message_type], tvb, 0, 0,
        MESSAGE_TYPE_REQUEST);
    PROTO_ITEM_SET_GENERATED(message_type_item);

    DISSECT_FIELD(cmd_data_size);
    DISSECT_FIELD(cmd_id);
    DISSECT_FIELD(cmd_version);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, LTTNG_LIVE_MODULE_SHORT_NAME);

    const guint header_size = pdu_offset;

    request->is_client = 1;
    request->cmd_id = cmd_id;

    col_add_fstr(pinfo->cinfo, COL_INFO,
        "%s Request",
        val_to_str(cmd_id, cmd_id_vals, "Unknown command (%d)"));

    proto_item_append_text(item, ": %s Request",
        val_to_str(cmd_id, cmd_id_vals, "Unknown command (%d)"));

    switch (cmd_id) {
    case CMD_ID_CONNECT: {
        DISSECT_FIELD(session_id);
        DISSECT_FIELD(protocol_version_major);
        DISSECT_FIELD(protocol_version_minor);
        DISSECT_FIELD(connection_type);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Protocol %u.%u, Type %u)",
            protocol_version_major, protocol_version_minor,
            connection_type);
        break;
    }
    case CMD_ID_LIST_SESSIONS:
        break;
    case CMD_ID_ATTACH_SESSION: {
        DISSECT_FIELD(session_id);
        DISSECT_FIELD(viewer_offset);
        DISSECT_FIELD(viewer_seek);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Session %lu, Offset %lu, Seek %u)",
            session_id, viewer_offset, viewer_seek);
        break;
    }
    case CMD_ID_GET_NEXT_INDEX: {
        DISSECT_FIELD(stream_id);
        request->stream_id = stream_id;
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Stream %lu)",
            stream_id);
        break;
    }
    case CMD_ID_GET_PACKET: {
        DISSECT_FIELD(stream_id);
        DISSECT_FIELD(stream_offset);
        DISSECT_FIELD(packet_length);
        request->stream_id = stream_id;
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Stream %lu, Offset %lu, Length %u)",
            stream_id, stream_offset, packet_length);
        break;
    }
    case CMD_ID_GET_METADATA: {
        DISSECT_FIELD(stream_id);
        request->stream_id = stream_id;
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Stream %lu)",
            stream_id);
        break;
    }
    case CMD_ID_GET_NEW_STREAMS: {
        DISSECT_FIELD(session_id);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Session %lu)",
            session_id);
        break;
    }
    case CMD_ID_CREATE_SESSION:
        break;
    default:
        DISSECT_LENGTH(cmd_data_size);
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    }

    DISSECTOR_ASSERT_CMPUINT((pdu_offset - header_size) , ==, cmd_data_size);
    return pdu_offset;
}


static guint
get_lttng_live_pdu_len_server(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint64_t request_frame_number = 0;
    lttng_live_frame_annotation_t * const request = find_client_request(
        pinfo->fd->num, &request_frame_number);
    if(request == NULL) {
        // TODO complain somehow
        return 0;
    }

    guint pdu_offset = 0;
    switch (request->cmd_id) {

    case CMD_ID_CONNECT: {
        ADVANCE_FIELD(session_id);
        ADVANCE_FIELD(protocol_version_major);
        ADVANCE_FIELD(protocol_version_minor);
        ADVANCE_FIELD(connection_type);
        return pdu_offset;
    }
    case CMD_ID_LIST_SESSIONS: {
        ADVANCE_FIELD_ASSIGN(sessions_count);
        for (uint32_t i = 0; i < sessions_count; i++) {
            ADVANCE_FIELD(session_id);
            ADVANCE_FIELD(live_timer);
            ADVANCE_FIELD(num_clients);
            ADVANCE_FIELD(num_streams);
            ADVANCE_FIELD(hostname_str);
            ADVANCE_FIELD(session_name_str);
        }
        return pdu_offset;
    }
    case CMD_ID_ATTACH_SESSION: {
        ADVANCE_FIELD(session_attach_status);
        ADVANCE_FIELD_ASSIGN(streams_count);
        for (uint32_t i = 0; i < streams_count; i++) {
            ADVANCE_FIELD(stream_id);
            ADVANCE_FIELD(ctf_trace_id);
            ADVANCE_FIELD(metadata_flag);
            ADVANCE_FIELD(path_name);
            ADVANCE_FIELD(channel_name);
        }
        return pdu_offset;
    }
    case CMD_ID_GET_NEXT_INDEX: {
        ADVANCE_FIELD(viewer_offset);
        ADVANCE_FIELD(packet_size);
        ADVANCE_FIELD(content_size);
        ADVANCE_FIELD(timestamp_begin);
        ADVANCE_FIELD(timestamp_end);
        ADVANCE_FIELD(events_discarded);
        ADVANCE_FIELD(stream_id);
        ADVANCE_FIELD(index_status);
        ADVANCE_FIELD(index_flags);
        return pdu_offset;
    }
    case CMD_ID_GET_PACKET: {
        ADVANCE_FIELD(packet_status);
        ADVANCE_FIELD_ASSIGN(packet_length);
        ADVANCE_FIELD(packet_flags);
        ADVANCE_LENGTH(packet_length);
        return pdu_offset;
    }
    case CMD_ID_GET_METADATA: {
        ADVANCE_FIELD_ASSIGN(metadata_length);
        ADVANCE_FIELD(metadata_status);
        ADVANCE_LENGTH(metadata_length);
        return pdu_offset;
    }
    case CMD_ID_GET_NEW_STREAMS: {
        ADVANCE_FIELD(new_streams_status);
        ADVANCE_FIELD_ASSIGN(streams_count);
        for (uint32_t i = 0; i < streams_count; i++) {
            ADVANCE_FIELD(stream_id);
            ADVANCE_FIELD(ctf_trace_id);
            ADVANCE_FIELD(metadata_flag);
            ADVANCE_FIELD(path_name);
            ADVANCE_FIELD(channel_name);
        }
        return pdu_offset;
    }
    case CMD_ID_CREATE_SESSION: {
        ADVANCE_FIELD(session_create_status);
        return pdu_offset;
    }
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        return 0;
    }
}

static int
dissect_lttng_live_pdu_server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint64_t request_frame_number = 0;
    lttng_live_frame_annotation_t * const request = find_client_request(
        pinfo->fd->num, &request_frame_number);
    if(request == NULL) {
        // TODO complain somehow
        return 0;
    }

    guint offset = 0;
    guint pdu_offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, LTTNG_LIVE_MODULE_SHORT_NAME);
    col_add_fstr(pinfo->cinfo, COL_INFO,
        "%s Reply",
        val_to_str(request->cmd_id, cmd_id_vals, "Unknown command (%d)"));

    proto_item *item = proto_tree_add_item(tree, lttng_live_proto, tvb, 0, -1, ENC_NA);
    proto_item_append_text(item, ": %s Reply",
        val_to_str(request->cmd_id, cmd_id_vals, "Unknown command (%d)"));

    proto_tree *subtree = proto_item_add_subtree(item, lttng_live_header_ett);

    proto_item * message_type_item = proto_tree_add_uint(subtree,
        lttng_hf[FIELD_message_type], tvb, 0, 0,
        MESSAGE_TYPE_REPLY);
    PROTO_ITEM_SET_GENERATED(message_type_item);

    proto_item * cmd_id_item = proto_tree_add_uint(subtree,
        lttng_hf[FIELD_cmd_id], tvb, 0, 0,
        request->cmd_id);
    PROTO_ITEM_SET_GENERATED(cmd_id_item);

    proto_item * request_frame_number_item = proto_tree_add_uint64(subtree,
        lttng_hf[FIELD_request_frame_number], tvb, 0, 0,
        request_frame_number);
    PROTO_ITEM_SET_GENERATED(request_frame_number_item);

    if (request->stream_id != 0) {
        proto_item * request_stream_id_item = proto_tree_add_uint64(subtree,
            lttng_hf[FIELD_request_stream_id], tvb, 0, 0,
            request->stream_id);
        PROTO_ITEM_SET_GENERATED(request_stream_id_item);
    }

    switch (request->cmd_id) {

    case CMD_ID_CONNECT: {
        DISSECT_FIELD(session_id);
        DISSECT_FIELD(protocol_version_major);
        DISSECT_FIELD(protocol_version_minor);
        DISSECT_FIELD(connection_type);
        col_append_fstr(pinfo->cinfo, COL_INFO,
            " (Protocol %u.%u, Type %u, Session %lu)",
            protocol_version_major, protocol_version_minor,
            connection_type, session_id);
        return pdu_offset;
    }
    case CMD_ID_LIST_SESSIONS: {
        DISSECT_FIELD(sessions_count);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%u sessions)", sessions_count);
        proto_tree *parent_tree = subtree;
        for (uint32_t i = 0; i < sessions_count; i++) {
            const guint subitem_start_offset = pdu_offset;
            proto_item *subitem = proto_tree_add_item(parent_tree,
                lttng_hf[FIELD_session_struct], tvb, offset + pdu_offset,
                -1, ENC_NA);
            proto_item_set_text(subitem, "Session #%u", i);
            subtree = proto_item_add_subtree(subitem, lttng_live_content_ett);
            DISSECT_FIELD(session_id);
            DISSECT_FIELD(live_timer);
            DISSECT_FIELD(num_clients);
            DISSECT_FIELD(num_streams);
            DISSECT_STRING(hostname_str);
            DISSECT_STRING(session_name_str);
            proto_item_append_text(subitem, ": Session %lu", session_id);
            proto_item_set_len(subitem, pdu_offset - subitem_start_offset);
        }
        return pdu_offset;
    }
    case CMD_ID_ATTACH_SESSION: {
        DISSECT_FIELD(session_attach_status);
        DISSECT_FIELD(streams_count);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Status %s, %u streams)",
            val_to_str(session_attach_status, session_attach_status_vals, "Unknown Status (%u)"),
            streams_count);
        proto_tree *parent_tree = subtree;
        for (uint32_t i = 0; i < streams_count; i++) {
            const guint subitem_start_offset = pdu_offset;
            proto_item *subitem = proto_tree_add_item(parent_tree,
                lttng_hf[FIELD_stream_struct], tvb, offset + pdu_offset,
                -1, ENC_NA);
            proto_item_set_text(subitem, "Stream #%u", i);
            subtree = proto_item_add_subtree(subitem, lttng_live_content_ett);
            DISSECT_FIELD(stream_id);
            DISSECT_FIELD(ctf_trace_id);
            DISSECT_FIELD(metadata_flag);
            DISSECT_STRING(path_name);
            DISSECT_STRING(channel_name);
            proto_item_append_text(subitem, ": Stream %lu", stream_id);
            proto_item_set_len(subitem, pdu_offset - subitem_start_offset);
        }
        return pdu_offset;
    }
    case CMD_ID_GET_NEXT_INDEX: {
        DISSECT_FIELD(viewer_offset);
        DISSECT_FIELD(packet_size);
        const size_t packet_size_bytes = packet_size / 8;
        {
            REWIND_FIELD(packet_size);
            proto_item * generated_item = proto_tree_add_uint64(subtree,
                lttng_hf[FIELD_packet_size_bytes], tvb,
                offset + pdu_offset, sizeof(TYPE_packet_size_bytes),
                packet_size_bytes);
            PROTO_ITEM_SET_GENERATED(generated_item);
            ADVANCE_FIELD(packet_size);
        }
        DISSECT_FIELD(content_size);
        const size_t content_size_bytes = content_size / 8;
        {
            REWIND_FIELD(content_size);
            proto_item * generated_item = proto_tree_add_uint64(subtree,
                lttng_hf[FIELD_content_size_bytes], tvb,
                offset + pdu_offset, sizeof(TYPE_content_size_bytes),
                content_size_bytes);
            PROTO_ITEM_SET_GENERATED(generated_item);
            ADVANCE_FIELD(content_size);
        }
        DISSECT_FIELD(timestamp_begin);
        DISSECT_FIELD(timestamp_end);
        DISSECT_FIELD(events_discarded);
        DISSECT_FIELD(stream_id); // XXX: always set to zero by lttng-relayd?
        DISSECT_FIELD(index_status);
        DISSECT_FIELD(index_flags);
        col_append_fstr(pinfo->cinfo, COL_INFO,
            " (Status %s, Flags %x, Offset %lu, Packet Size %lu, Content Size %lu)",
            val_to_str(index_status, index_status_vals, "Unknown Status (%u)"),
            index_flags, viewer_offset, packet_size_bytes, content_size_bytes);
        return pdu_offset;
    }
    case CMD_ID_GET_PACKET: {
        DISSECT_FIELD(packet_status);
        DISSECT_FIELD(packet_length);
        DISSECT_FIELD(packet_flags);
        DISSECT_LENGTH(packet_length);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Status %s, Flags %x, Length %u)",
            val_to_str(packet_status, packet_status_vals, "Unknown Status (%u)"),
            packet_flags, packet_length);
        return pdu_offset;
    }
    case CMD_ID_GET_METADATA: {
        DISSECT_FIELD(metadata_length);
        DISSECT_FIELD(metadata_status);
        DISSECT_LENGTH(metadata_length);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Status %s, Length %lu)",
            val_to_str(metadata_status, metadata_status_vals, "Unknown Status (%u)"),
            metadata_length);
        return pdu_offset;
    }
    case CMD_ID_GET_NEW_STREAMS: {
        DISSECT_FIELD(new_streams_status);
        DISSECT_FIELD(streams_count);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Status %s, %u streams)",
            val_to_str(new_streams_status, new_streams_status_vals, "Unknown Status (%u)"),
            streams_count);
        proto_tree *parent_tree = subtree;
        for (uint32_t i = 0; i < streams_count; i++) {
            const guint subitem_start_offset = pdu_offset;
            proto_item *subitem = proto_tree_add_item(parent_tree,
                lttng_hf[FIELD_stream_struct], tvb, offset + pdu_offset,
                -1, ENC_NA);
            proto_item_set_text(subitem, "Stream #%u", i);
            subtree = proto_item_add_subtree(subitem, lttng_live_content_ett);
            DISSECT_FIELD(stream_id);
            DISSECT_FIELD(ctf_trace_id);
            DISSECT_FIELD(metadata_flag);
            DISSECT_STRING(path_name);
            DISSECT_STRING(channel_name);
            proto_item_append_text(subitem, ": Stream %lu", stream_id);
            proto_item_set_len(subitem, pdu_offset - subitem_start_offset);
        }
        return pdu_offset;
    }
    case CMD_ID_CREATE_SESSION: {
        DISSECT_FIELD(session_create_status);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Status %s)",
            val_to_str(session_create_status, session_create_status_vals, "Unknown Status (%u)"));
        return pdu_offset;
    }
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        return 0;
    }
}

int
lttng_live_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    lttng_conversation_t *conversation = get_lttng_conversation(pinfo, lttng_live_proto);
    if (addresses_equal(&conversation->initiator_addr, &pinfo->src)
            && conversation->initiator_port == pinfo->srcport) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
            get_lttng_live_pdu_len_client, dissect_lttng_live_pdu_client, conversation);
    } else if (addresses_equal(&conversation->initiator_addr, &pinfo->dst)
            && conversation->initiator_port == pinfo->destport) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
            get_lttng_live_pdu_len_server, dissect_lttng_live_pdu_server, conversation);
    } else {
        DISSECTOR_ASSERT_NOT_REACHED();
    }
    return tvb_reported_length(tvb);
}

void lttng_live_proto_register(void)
{
    lttng_live_proto = proto_register_protocol(
            LTTNG_LIVE_MODULE_NAME,
            LTTNG_LIVE_MODULE_SHORT_NAME,
            LTTNG_LIVE_MODULE_FILTER_NAME);

    static hf_register_info hf[] = {
#define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) \
        { &lttng_hf[FIELD_##name], \
          { descr, "lttng_live." #name, wstype, wsdisplay, wsstrings, 0, NULL, HFILL } },
#include "fields-lttng_live.h"
#undef FIELD
    };
    proto_register_field_array(lttng_live_proto, hf, array_length(hf));

    static gint *ett[] = {
        &lttng_live_header_ett,
        &lttng_live_content_ett,
    };
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector(LTTNG_LIVE_MODULE_FILTER_NAME, lttng_live_dissect, lttng_live_proto);
}

void lttng_live_proto_reg_handoff(void)
{
    static dissector_handle_t lttng_live_handle = NULL;
    static gboolean initialized = FALSE;
    if (!initialized) {
        lttng_live_handle = create_dissector_handle(lttng_live_dissect, lttng_live_proto);
        dissector_add_uint("tcp.port", LTTNG_LIVE_TCP_PORT, lttng_live_handle);
        initialized = TRUE;
    }
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
