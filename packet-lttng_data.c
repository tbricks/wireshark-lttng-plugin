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
 * packet-lttng_data.c
 * Routines for LTTng Data protocol dissection
 *
 * LTTng Data protocol is defined in
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
#include "packet-lttng_data.h"

#define LTTNG_DATA_TCP_PORT 5343
#define LTTNG_DATA_MODULE_NAME         LTTNG_MODULE_NAME "_Data"
#define LTTNG_DATA_MODULE_SHORT_NAME   LTTNG_MODULE_SHORT_NAME "_Data"
#define LTTNG_DATA_MODULE_FILTER_NAME  LTTNG_MODULE_FILTER_NAME "_data"

static int lttng_data_proto = -1;
static int lttng_data_header_ett = -1;
static int lttng_data_content_ett = -1;

static int lttng_hf[] = {
    #define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) -1,
        #include "fields-lttng_data.h"
    #undef FIELD
};

typedef enum lttng_data_field {
    #define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) FIELD_##name,
        #include "fields-lttng_data.h"
    #undef FIELD
} lttng_data_field_t;

#define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) typedef type TYPE_##name;
    #include "fields-lttng_data.h"
#undef FIELD

static guint
get_lttng_data_pdu_len_client(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint pdu_offset = 0;
    ADVANCE_FIELD(circuit_id);
    ADVANCE_FIELD(stream_id);
    ADVANCE_FIELD(net_seq_num);
    ADVANCE_FIELD_ASSIGN(data_size);
    ADVANCE_FIELD(padding_size);
    ADVANCE_LENGTH(data_size);
    return pdu_offset;
}

static int
dissect_lttng_data_pdu_client(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    guint pdu_offset = 0;

    proto_item *item = proto_tree_add_item(tree, lttng_data_proto, tvb, 0, -1, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(item, lttng_data_header_ett);

    DISSECT_FIELD(circuit_id);
    DISSECT_FIELD(stream_id);
    DISSECT_FIELD(net_seq_num);
    DISSECT_FIELD(data_size);
    DISSECT_FIELD(padding_size);
    const guint header_size = pdu_offset;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, LTTNG_DATA_MODULE_SHORT_NAME);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Data" \
        " (Stream Id %lu, Net Seq Num %lu, Size %u)",
        stream_id, net_seq_num, data_size);

    proto_item_append_text(item, " (%u bytes)", data_size);

    DISSECT_LENGTH(data_size);

    col_set_fence(pinfo->cinfo, COL_INFO);

    DISSECTOR_ASSERT_CMPUINT((pdu_offset - header_size) , ==, data_size);
    return pdu_offset;
}

static guint
get_lttng_data_pdu_len_server(packet_info *pinfo _U_, tvbuff_t *tvb _U_, int offset _U_, void *data _U_)
{
    DISSECTOR_ASSERT_NOT_REACHED();
    return 0;
}

static int
dissect_lttng_data_pdu_server(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    DISSECTOR_ASSERT_NOT_REACHED();
    return 0;
}

int
lttng_data_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    lttng_conversation_t *conversation = get_lttng_conversation(pinfo, lttng_data_proto);
    if (addresses_equal(&conversation->initiator_addr, &pinfo->src)
            && conversation->initiator_port == pinfo->srcport) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
            get_lttng_data_pdu_len_client, dissect_lttng_data_pdu_client, conversation);
    } else if (addresses_equal(&conversation->initiator_addr, &pinfo->dst)
            && conversation->initiator_port == pinfo->destport) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0,
            get_lttng_data_pdu_len_server, dissect_lttng_data_pdu_server, conversation);
    } else {
        DISSECTOR_ASSERT_NOT_REACHED();
    }
    return tvb_reported_length(tvb);
}

void lttng_data_proto_register(void)
{
    lttng_data_proto = proto_register_protocol(
            LTTNG_DATA_MODULE_NAME,
            LTTNG_DATA_MODULE_SHORT_NAME,
            LTTNG_DATA_MODULE_FILTER_NAME);

    static hf_register_info hf[] = {
#define FIELD(name, type, wstype, wsdisplay, wsstrings, descr) \
        { &lttng_hf[FIELD_##name], \
          { descr, "lttng_data." #name, wstype, wsdisplay, wsstrings, 0, NULL, HFILL } },
#include "fields-lttng_data.h"
#undef FIELD
    };
    proto_register_field_array(lttng_data_proto, hf, array_length(hf));

    static gint *ett[] = {
        &lttng_data_header_ett,
        &lttng_data_content_ett,
    };
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector(LTTNG_DATA_MODULE_FILTER_NAME, lttng_data_dissect, lttng_data_proto);
}

void lttng_data_proto_reg_handoff(void)
{
    static dissector_handle_t lttng_data_handle = NULL;
    static gboolean initialized = FALSE;
    if (!initialized) {
        lttng_data_handle = create_dissector_handle(lttng_data_dissect, lttng_data_proto);
        dissector_add_uint("tcp.port", LTTNG_DATA_TCP_PORT, lttng_data_handle);
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
