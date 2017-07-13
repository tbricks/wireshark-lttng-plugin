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
 * packet-lttng_control.c
 * Routines for LTTng Control protocol dissection
 *
 * LTTng Control protocol is defined in
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/src/common/sessiond-comm/relayd.h
 * https://github.com/lttng/lttng-tools/blob/stable-2.7/src/common/sessiond-comm/sessiond-comm.h
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
#include "packet-lttng_control.h"

typedef char channel_name_t[256+8];
typedef char path_name_t[4096]; /* as per PATH_MAX */

#define LTTNG_CONTROL_TCP_PORT 5342
#define LTTNG_CONTROL_MODULE_NAME         LTTNG_MODULE_NAME "_Control"
#define LTTNG_CONTROL_MODULE_SHORT_NAME   LTTNG_MODULE_SHORT_NAME "_Control"
#define LTTNG_CONTROL_MODULE_FILTER_NAME  LTTNG_MODULE_FILTER_NAME "_control"

static int lttng_control_proto = -1;
static int lttng_control_header_ett = -1;
static int lttng_control_content_ett = -1;

static int lttng_hf[] = {
    #define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) -1,
        #include "fields-lttng_control.h"
    #undef FIELD
};

typedef enum lttng_control_field {
    #define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) FIELD_##name,
        #include "fields-lttng_control.h"
    #undef FIELD
} lttng_control_field_t;

#define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) typedef type TYPE_##name;
    #include "fields-lttng_control.h"
#undef FIELD

enum lttng_control_cmd_id {
    CMD_ID_ADD_STREAM = 1,
    CMD_ID_CREATE_SESSION = 2,
    CMD_ID_START_DATA = 3,
    CMD_ID_UPDATE_SYNC_INFO = 4,
    CMD_ID_VERSION = 5,
    CMD_ID_SEND_METADATA = 6,
    CMD_ID_CLOSE_STREAM = 7,
    CMD_ID_DATA_PENDING = 8,
    CMD_ID_QUIESCENT_CONTROL = 9,
    CMD_ID_BEGIN_DATA_PENDING = 10,
    CMD_ID_END_DATA_PENDING = 11,
    CMD_ID_ADD_INDEX = 12,
    CMD_ID_SEND_INDEX = 13,
    CMD_ID_CLOSE_INDEX = 14,
    CMD_ID_LIST_SESSIONS = 15,
    CMD_ID_STREAMS_SENT = 16,
};

static const value_string cmd_id_vals[] = {
    { CMD_ID_ADD_STREAM, "Add Stream" },
    { CMD_ID_CREATE_SESSION, "Create Session" },
    { CMD_ID_START_DATA, "Start Data" },
    { CMD_ID_UPDATE_SYNC_INFO, "Update Sync Info" },
    { CMD_ID_VERSION, "Version" },
    { CMD_ID_SEND_METADATA, "Send Metadata" },
    { CMD_ID_CLOSE_STREAM, "Close Stream" },
    { CMD_ID_DATA_PENDING, "Data Pending" },
    { CMD_ID_QUIESCENT_CONTROL, "Quiescent Control" },
    { CMD_ID_BEGIN_DATA_PENDING, "Begin Data Pending" },
    { CMD_ID_END_DATA_PENDING, "End Data Pending" },
    { CMD_ID_ADD_INDEX, "Add Index" },
    { CMD_ID_SEND_INDEX, "Send Index" },
    { CMD_ID_CLOSE_INDEX, "Close Index" },
    { CMD_ID_LIST_SESSIONS, "List Sessions" },
    { CMD_ID_STREAMS_SENT, "Streams Sent" },
    { 0, NULL},
};

/* According to enum lttng_error_code */
static const value_string return_code_vals[] = {
    { 10, "Success" },
    { 0, NULL },
};

typedef struct lttng_control_frame_annotation {
    unsigned int is_client:1;
    unsigned int cmd_id:5; /* currently we have only 16 commands */
} lttng_control_frame_annotation_t;

#define MAX_NUM_FRAMES 1000000
static lttng_control_frame_annotation_t frames[MAX_NUM_FRAMES];

static guint
get_lttng_control_pdu_len_client(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint pdu_offset = 0;
    ADVANCE_FIELD_ASSIGN(circuit_id);
    ADVANCE_FIELD_ASSIGN(cmd_data_size);
    ADVANCE_FIELD(cmd_id);
    ADVANCE_FIELD(cmd_version);
    ADVANCE_LENGTH(cmd_data_size);
    return pdu_offset;
}

static int
dissect_lttng_control_pdu_client(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    guint pdu_offset = 0;

    proto_item *item = proto_tree_add_item(tree, lttng_control_proto, tvb, 0, -1, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(item, lttng_control_header_ett);

    DISSECT_FIELD(circuit_id);
    DISSECT_FIELD(cmd_data_size);
    DISSECT_FIELD(cmd_id);
    DISSECT_FIELD(cmd_version);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, LTTNG_CONTROL_MODULE_SHORT_NAME);

    const guint header_size = pdu_offset;

    if(pinfo->fd->num < MAX_NUM_FRAMES) {
        frames[pinfo->fd->num].is_client = 1;
        frames[pinfo->fd->num].cmd_id = cmd_id;
    }

    col_add_fstr(pinfo->cinfo, COL_INFO,
        "%s Request",
        val_to_str(cmd_id, cmd_id_vals, "Unknown command (%d)"));

    proto_item_append_text(item, ": %s Request",
        val_to_str(cmd_id, cmd_id_vals, "Unknown command (%d)"));

    switch (cmd_id) {
    case CMD_ID_ADD_STREAM: {
        DISSECT_STRING(channel_name);
        DISSECT_STRING(path_name);
        DISSECT_FIELD(tracefile_size);
        DISSECT_FIELD(tracefile_count);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Channel %s)", channel_name);
        break;
    }
    case CMD_ID_STREAMS_SENT:
        break;
    case CMD_ID_SEND_METADATA: {
        DISSECT_FIELD(stream_id);
        DISSECT_FIELD(padding_size);
        const guint metadata_header_size = pdu_offset - header_size;
        DISSECTOR_ASSERT_CMPUINT(cmd_data_size, >, metadata_header_size);
        const guint metadata_size = cmd_data_size - metadata_header_size;
        DISSECT_LENGTH(metadata_size);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Stream Id %lu, Size %u)",
            stream_id, metadata_size);
        break;
    }
    case CMD_ID_SEND_INDEX: {
        DISSECT_FIELD(relay_stream_id);
        DISSECT_FIELD(net_seq_num);
        DISSECT_FIELD(packet_size);
        DISSECT_FIELD(content_size);
        DISSECT_FIELD(timestamp_begin);
        DISSECT_FIELD(timestamp_end);
        DISSECT_FIELD(events_discarded);
        DISSECT_FIELD(stream_id);
        // XXX We seem to receive some unknown trailing data. Handle it to avoid assert
        if ((cmd_data_size + header_size) > pdu_offset) {
            const guint trailing_size = (cmd_data_size + header_size) - pdu_offset;
            DISSECT_LENGTH(trailing_size);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Relay Stream Id %lu, " \
            "Net Seq Num %lu, Packet Size %lu, Content Size %lu)",
            relay_stream_id, net_seq_num, packet_size, content_size);
        break;
    }
    // TODO Handle rest of the commands
    default:
        DISSECT_LENGTH(cmd_data_size);
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    }

    col_set_fence(pinfo->cinfo, COL_INFO);

    DISSECTOR_ASSERT_CMPUINT((pdu_offset - header_size) , ==, cmd_data_size);
    return pdu_offset;
}

static int find_previous_client_cmd_id(int current_frame) {
    int cmd_id = 0;
    if(current_frame < MAX_NUM_FRAMES) {
        for (size_t i = current_frame - 1; i > 0; i--) {
            if(frames[i].is_client) {
                cmd_id = frames[i].cmd_id;
                break;
            }
        }
    }
    return cmd_id;
}

static guint
get_lttng_control_pdu_len_server(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
    int client_cmd_id = find_previous_client_cmd_id(pinfo->fd->num);
    if(!client_cmd_id) {
        // TODO complain somehow
        return 0;
    }

    guint pdu_offset = 0;
    switch (client_cmd_id) {

    case CMD_ID_ADD_STREAM: {
        ADVANCE_FIELD(handle);
        ADVANCE_FIELD(return_code);
        return pdu_offset;
    }
    case CMD_ID_STREAMS_SENT: {
        ADVANCE_FIELD(return_code);
        return pdu_offset;
    }
    case CMD_ID_SEND_INDEX: {
        ADVANCE_FIELD(return_code);
        return pdu_offset;
    }
    // TODO Handle rest of the commands
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        return 0;
    }
}

static int
dissect_lttng_control_pdu_server(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int client_cmd_id = find_previous_client_cmd_id(pinfo->fd->num);
    if(!client_cmd_id) {
        // TODO complain somehow
        return 0;
    }

    guint offset = 0;
    guint pdu_offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, LTTNG_CONTROL_MODULE_SHORT_NAME);
    col_add_fstr(pinfo->cinfo, COL_INFO,
        "%s Reply",
        val_to_str(client_cmd_id, cmd_id_vals, "Unknown command (%d)"));

    proto_item *item = proto_tree_add_item(tree, lttng_control_proto, tvb, 0, -1, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(item, lttng_control_header_ett);

    proto_item_append_text(item, ": %s Reply",
        val_to_str(client_cmd_id, cmd_id_vals, "Unknown command (%d)"));

    switch (client_cmd_id) {
    case CMD_ID_ADD_STREAM: {
        DISSECT_FIELD(handle);
        DISSECT_FIELD(return_code);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Status %s, Handle %lu)",
            val_to_str(return_code, return_code_vals, "Unknown return core (%d)"),
            handle);
        return pdu_offset;
    }
    case CMD_ID_STREAMS_SENT: {
        DISSECT_FIELD(return_code);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Status %s)",
            val_to_str(return_code, return_code_vals, "Unknown return core (%d)"));
        return pdu_offset;
    }
    case CMD_ID_SEND_INDEX: {
        DISSECT_FIELD(return_code);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (Status %s)",
            val_to_str(return_code, return_code_vals, "Unknown return core (%d)"));
        return pdu_offset;
    }
    // TODO Handle rest of the commands
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        return 0;
    }
}

int
lttng_control_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    lttng_conversation_t *conversation = get_lttng_conversation(pinfo, lttng_control_proto);
    if (addresses_equal(&conversation->initiator_addr, &pinfo->src)
            && conversation->initiator_port == pinfo->srcport) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
            get_lttng_control_pdu_len_client, dissect_lttng_control_pdu_client, conversation);
    } else if (addresses_equal(&conversation->initiator_addr, &pinfo->dst)
            && conversation->initiator_port == pinfo->destport) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
            get_lttng_control_pdu_len_server, dissect_lttng_control_pdu_server, conversation);
    } else {
        DISSECTOR_ASSERT_NOT_REACHED();
    }
    return tvb_reported_length(tvb);
}

void lttng_control_proto_register(void)
{
    lttng_control_proto = proto_register_protocol(
            LTTNG_CONTROL_MODULE_NAME,
            LTTNG_CONTROL_MODULE_SHORT_NAME,
            LTTNG_CONTROL_MODULE_FILTER_NAME);

    static hf_register_info hf[] = {
#define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) \
        { &lttng_hf[FIELD_##name], \
          { descr, "lttng_control." #name, wstype, wsdisplay, wsstrings, 0, NULL, HFILL } },
#include "fields-lttng_control.h"
#undef FIELD
    };
    proto_register_field_array(lttng_control_proto, hf, array_length(hf));

    static gint *ett[] = {
        &lttng_control_header_ett,
        &lttng_control_content_ett,
    };
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector(LTTNG_CONTROL_MODULE_FILTER_NAME, lttng_control_dissect, lttng_control_proto);
}

void lttng_control_proto_reg_handoff(void)
{
    static dissector_handle_t lttng_control_handle = NULL;
    static gboolean initialized = FALSE;
    if (!initialized) {
        lttng_control_handle = create_dissector_handle(lttng_control_dissect, lttng_control_proto);
        dissector_add_uint("tcp.port", LTTNG_CONTROL_TCP_PORT, lttng_control_handle);
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
