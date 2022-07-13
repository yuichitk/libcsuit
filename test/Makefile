#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

CFLAGS	= -Wall
LDFLAGS	= -L../ -lcsuit -lt_cose -lqcbor -lcunit -lm
INC		= -I ../inc/
TARGET	= ./libcsuit_test
RESULT	= result.txt

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS	+= -DLIBCSUIT_PSA_CRYPTO_C=1
    LDFLAGS	+= -lmbedtls -lmbedx509 -lmbedcrypto
else
    # use OpenSSL
    LDFLAGS += -lcrypto
endif

.PHONY: all run clean

all: $(TARGET)

$(TARGET):
	$(CC) -o $@ main.c $(CFLAGS) $(LDFLAGS) $(INC)

$(RESULT): $(TARGET)
	$(TARGET) > $(RESULT)

run: $(RESULT)
	cat $(RESULT)
	$(eval RES := $(shell cat $(RESULT) | head -n-2 | tail -n+4 | awk '{print $$5}' | paste -s | sed 's/\t//g'))
	exit $(RES)

clean:
	$(RM) $(TARGET) $(RESULT)
