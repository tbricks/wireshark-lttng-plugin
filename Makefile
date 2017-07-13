# The wireshark-lttng-plugin -- a dissector for LTTng Live protocols
# Copyright (C) 2017 Itiviti AB
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
# LTTng is an open source software developed by EfficiOS Inc.
# http://lttng.org/
# http://www.efficios.com/about-efficios
#
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs

WIRESHARK_PERSONAL_PLUGINS_DIR := $(HOME)/.config/wireshark/plugins

GLIB_INC_DIRS := /usr/include/glib-2.0 /usr/lib64/glib-2.0/include
WIRESHARK_INC_DIRS := /usr/include/wireshark

CPPFLAGS := $(addprefix -I,$(GLIB_INC_DIRS) $(WIRESHARK_INC_DIRS))
CFLAGS := -std=c99 -pedantic -Wall -Wextra -fPIC -g
LDFLAGS := -shared -g

PLUGIN_FILE := packet-lttng.so
OBJS := moduleinfo.o \
	packet-lttng_control.o \
	packet-lttng_data.o \
	packet-lttng_live.o \


.PHONY: all
all: $(PLUGIN_FILE)

$(PLUGIN_FILE): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -rf $(PLUGIN_FILE)
	rm -rf $(OBJS)

.PHONY: install
install: $(PLUGIN_FILE)
	mkdir -p $(WIRESHARK_PERSONAL_PLUGINS_DIR)
	install -m 755 $(PLUGIN_FILE) $(WIRESHARK_PERSONAL_PLUGINS_DIR)

