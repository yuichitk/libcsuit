#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

CC		= gcc
CFLAGS	= -Wall -g -fPIC
LDFLAGS	= -lt_cose -lqcbor
INC		= -I ./inc
SRCS	= examples/suit_manifest_parser_main.c src/suit_manifest_print.c src/suit_common.c src/suit_manifest_data.c
OBJDIR	= ./obj
OBJS	= $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(SRCS)))

.PHONY: all so install uninstall clean

all: libcsuit.a

so: libcsuit.so

libcsuit.a: $(OBJS)
	$(AR) -r $@ $^

libcsuit.so: $(OBJS)
	$(CC) -shared $^ $(CFLAGS) $(INC) -o $@

PUBLIC_INTERFACE=inc/csuit.h inc/suit_common.h inc/suit_manifest_data.h inc/suit_manifest_print.h

$(OBJDIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

define install-header
	install -m 644 $1 $2/$(nodir $1)

endef

install: libcsuit.a $(PUBLIC_INTERFACE)
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -m 644 libcsuit.a $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/csuit
	$(foreach header,$(PUBLIC_INTERFACE),$(call install-header,$(header),$(DESTDIR)$(PREFIX)/include/csuit))

install_so: libcsuit.so
	install -m 755 libcsuit.so $(DESTDIR)$(PREFIX)/lib/libcsuit.so.1.0.0
	ln -sf libcsuit.so.1 $(DESTDIR)$(PREFIX)/lib/libcsuit.so
	ln -sf libcsuit.so.1.0.0 $(DESTDIR)$(PREFIX)/liblibcsuit.so.1

uninstall: libcsuit.a $(PUBLIC_INTERFACE)
	$(RM) -d $(DESTDIR)$(PREFIX)/include/csuit/*
	$(RM) -d $(DESTDIR)$(PREFIX)/include/csuit/
	$(RM) $(addprefix $(DESTDIR)$(PREFIX)/lib/, \
		libcsuit.a libcsuit.so libcsuit.co.1 libcsuit.so.1.0.0)

clean:
	rm -f $(OBJS) libcsuit.a libcsuit.so

