#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

NAME				= libcsuit
CFLAGS				= -Wall -fPIC
LDFLAGS				= -lt_cose -lqcbor -lm
INC					= -I ./inc
SRCS				= src/suit_common.c src/suit_manifest_process.c src/suit_manifest_decode.c src/suit_manifest_encode.c src/suit_manifest_print.c src/suit_cose.c src/suit_digest.c
PUBLIC_INTERFACE	= inc/csuit/csuit.h inc/csuit/suit_common.h inc/csuit/suit_manifest_data.h inc/csuit/suit_manifest_process.h inc/csuit/suit_manifest_print.h inc/csuit/suit_cose.h inc/csuit/suit_digest.h
OBJDIR				= ./obj
OBJS				= $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(SRCS)))

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS	+= -DLIBCSUIT_PSA_CRYPTO_C=1
    LDFLAGS	+= -lmbedtls -lmbedx509 -lmbedcrypto
else
    # use OpenSSL
    MBEDTLS=0
    LDFLAGS += -lcrypto
endif

.PHONY: all so doc install uninstall test clean

all: ./bin/$(NAME).a build_test

so: ./bin/$(NAME).so

doc:
	doxygen Doxyfile

./bin/$(NAME).a: $(OBJS)
	$(AR) -r $@ $^

./bin/$(NAME).so: $(OBJS)
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

install: ./bin/$(NAME).a $(PUBLIC_INTERFACE)
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -m 644 ./bin/$(NAME).a $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/csuit
	$(foreach header,$(PUBLIC_INTERFACE),$(call install-header,$(header),$(DESTDIR)$(PREFIX)/include/csuit))

install_so: ./bin/$(NAME).so
	install -m 755 ./bin/$(NAME).so $(DESTDIR)$(PREFIX)/lib/$(NAME).so.1.0.0
	ln -sf ./bin/$(NAME).so.1 $(DESTDIR)$(PREFIX)/lib/$(NAME).so
	ln -sf ./bin/$(NAME).so.1.0.0 $(DESTDIR)$(PREFIX)/lib$(NAME).so.1

uninstall:
	$(RM) -d $(DESTDIR)$(PREFIX)/include/csuit/*
	$(RM) -d $(DESTDIR)$(PREFIX)/include/csuit/
	$(RM) $(addprefix $(DESTDIR)$(PREFIX)/lib/, \
		$(NAME).a $(NAME).so $(NAME).so.1 $(NAME).so.1.0.0)

build_test:
	$(MAKE) -C test MBEDTLS=$(MBEDTLS)

test: ./bin/$(NAME).a
	$(MAKE) -C test MBEDTLS=$(MBEDTLS) run

clean:
	$(RM) -f $(OBJS) ./bin/$(NAME).a ./bin/$(NAME).so
	$(MAKE) -C test clean
