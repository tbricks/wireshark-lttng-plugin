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
 * packet-lttng_common.h
 * Common code for LTTng protocol dissectors
 */
#ifndef WS_LTTNG_PACKET_LTTNG_COMMON_H
#define WS_LTTNG_PACKET_LTTNG_COMMON_H

#include <stdint.h>
#include <assert.h>
#include <gmodule.h>       /* Glib */
#include <config.h>        /* Wireshark's config header */
#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */

typedef struct lttng_conversation {
    address initiator_addr;
    guint32 initiator_port;
} lttng_conversation_t;

static lttng_conversation_t *
get_lttng_conversation(packet_info *pinfo, int proto)
{
  conversation_t *ws_conversation = find_or_create_conversation(pinfo);
  lttng_conversation_t *conversation = conversation_get_proto_data(ws_conversation, proto);
  if (conversation == NULL) {
    conversation = wmem_new0(wmem_file_scope(), lttng_conversation_t);
    copy_address_wmem(wmem_file_scope(), &conversation->initiator_addr, &pinfo->src);
    conversation->initiator_port = pinfo->srcport;
    conversation_add_proto_data(ws_conversation, proto, conversation);
  }
  return conversation;
}

/* Polymorphic hack for cleaner fields parsing code */
static uint64_t
tvb_get_as_uint64(tvbuff_t *tvb,  const gint offset, const guint encoding, const size_t size)
{
  if (size == 1)
      return (uint64_t) tvb_get_guint8(tvb, offset);
  else if (size == 2)
      return (uint64_t) tvb_get_guint16(tvb, offset, encoding);
  else if (size == 4)
      return (uint64_t) tvb_get_guint32(tvb, offset, encoding);
  else if (size == 8)
      return (uint64_t) tvb_get_guint64(tvb, offset, encoding);
  else
      assert(0); // should be unreachable
}

#define ADVANCE_FIELD(name_) \
    if ((guint)tvb_captured_length_remaining(tvb, offset + pdu_offset) < sizeof(TYPE_##name_)) \
        return 0; \
    pdu_offset += sizeof(TYPE_##name_);

#define ADVANCE_FIELD_ASSIGN(name_) \
    if ((guint)tvb_captured_length_remaining(tvb, offset + pdu_offset) < sizeof(TYPE_##name_)) \
        return 0; \
    TYPE_##name_ name_ = (TYPE_##name_)tvb_get_as_uint64(tvb, offset + pdu_offset, ENC_BIG_ENDIAN, sizeof(TYPE_##name_)); \
    (void) name_; \
    pdu_offset += sizeof(TYPE_##name_);

#define ADVANCE_FIELD(name_) \
    if ((guint)tvb_captured_length_remaining(tvb, offset + pdu_offset) < sizeof(TYPE_##name_)) \
        return 0; \
    pdu_offset += sizeof(TYPE_##name_);

#define ADVANCE_OPAQUE(type_) \
    if ((guint)tvb_captured_length_remaining(tvb, offset + pdu_offset) < sizeof(type_)) \
        return 0; \
    pdu_offset += sizeof(type_);

#define ADVANCE_LENGTH(len_) \
    if ((guint)tvb_captured_length_remaining(tvb, offset + pdu_offset) < len_) \
        return 0; \
    pdu_offset += len_;

#define REWIND_FIELD(name_) \
    pdu_offset -= sizeof(TYPE_##name_);

#define DISSECT_FIELD(name_) \
    if ((guint)tvb_captured_length_remaining(tvb, offset + pdu_offset) < sizeof(TYPE_##name_)) \
        return -(ssize_t)sizeof(TYPE_##name_); \
    TYPE_##name_ name_ = (TYPE_##name_)tvb_get_as_uint64(tvb, offset + pdu_offset, ENC_BIG_ENDIAN, sizeof(TYPE_##name_)); \
    (void) name_; \
    proto_tree_add_item(subtree, lttng_hf[FIELD_##name_], tvb, offset + pdu_offset, \
        sizeof(TYPE_##name_), ENC_BIG_ENDIAN); \
    pdu_offset += sizeof(TYPE_##name_);

#define DISSECT_STRING(name_) \
    if ((guint)tvb_captured_length_remaining(tvb, offset + pdu_offset) < sizeof(TYPE_##name_)) \
        return -(ssize_t)sizeof(TYPE_##name_); \
    TYPE_##name_ name_; \
    {   gint str_length = 0; \
        const guint8 *str_ptr = tvb_get_const_stringz(tvb, offset + pdu_offset, &str_length); \
        strncpy(name_, (const char *)str_ptr, sizeof(TYPE_##name_)); \
    } \
    name_[sizeof(TYPE_##name_)-1] = '\0'; \
    proto_tree_add_item(subtree, lttng_hf[FIELD_##name_], tvb, offset + pdu_offset, \
        sizeof(TYPE_##name_), ENC_ASCII); \
    pdu_offset += sizeof(TYPE_##name_);

#define DISSECT_OPAQUE(type_) \
    if ((guint)tvb_captured_length_remaining(tvb, offset + pdu_offset) < sizeof(type_)) \
        return -(ssize_t)sizeof(type_); \
    pdu_offset += sizeof(type_);

#define DISSECT_LENGTH(len_) \
    if ((guint)tvb_captured_length_remaining(tvb, offset + pdu_offset) < len_) \
        return -(ssize_t)len_; \
    pdu_offset += len_;

#endif /* WS_LTTNG_PACKET_LTTNG_COMMON_H */

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
