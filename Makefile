#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

NAME				= libcsuit
CC					= gcc
CFLAGS				= -Wall -fPIC
LDFLAGS				= -lt_cose -lqcbor
INC					= -I ./inc -I ./t_cose/inc
SRCS				= src/suit_common.c src/suit_manifest_process.c src/suit_manifest_decode.c src/suit_manifest_encode.c src/suit_manifest_print.c src/suit_cose.c src/suit_digest.c
PUBLIC_INTERFACE	= inc/csuit/csuit.h inc/csuit/suit_common.h inc/csuit/suit_manifest_data.h inc/csuit/suit_manifest_process.h inc/csuit/suit_manifest_print.h inc/csuit/suit_cose.h inc/csuit/suit_digest.h
OBJDIR				= ./obj
OBJS				= $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(SRCS)))

.PHONY: all so doc install uninstall clean

all: $(NAME).a

so: $(NAME).so

doc:
	doxygen Doxyfile

$(NAME).a: $(OBJS)
	$(AR) -r $@ $^

$(NAME).so: $(OBJS)
	$(CC) -shared $^ $(CFLAGS) $(INC) -o $@


$(OBJDIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

define install-header
	install -m 644 $1 $2/$(nodir $1)

endef

install: $(NAME).a $(PUBLIC_INTERFACE)
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -m 644 $(NAME).a $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/csuit
	$(foreach header,$(PUBLIC_INTERFACE),$(call install-header,$(header),$(DESTDIR)$(PREFIX)/include/csuit))

install_so: $(NAME).so
	install -m 755 $(NAME).so $(DESTDIR)$(PREFIX)/lib/$(NAME).so.1.0.0
	ln -sf $(NAME).so.1 $(DESTDIR)$(PREFIX)/lib/$(NAME).so
	ln -sf $(NAME).so.1.0.0 $(DESTDIR)$(PREFIX)/lib$(NAME).so.1

uninstall: $(NAME).a $(PUBLIC_INTERFACE)
	$(RM) -d $(DESTDIR)$(PREFIX)/include/csuit/*
	$(RM) -d $(DESTDIR)$(PREFIX)/include/csuit/
	$(RM) $(addprefix $(DESTDIR)$(PREFIX)/lib/, \
		$(NAME).a $(NAME).so $(NAME).so.1 $(NAME).so.1.0.0)

clean:
	rm -f $(OBJS) $(NAME).a $(NAME).so

