#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

CFLAGS	= -Wall
LDFLAGS	= -lt_cose -lqcbor -lcrypto -lcunit -lm
INC		= -I ../inc/
TARGET	= ./libcsuit_test
SRCS	= ../src/suit_common.c ../src/suit_manifest_process.c ../src/suit_manifest_decode.c ../src/suit_manifest_encode.c ../src/suit_manifest_print.c ../src/suit_cose.c ../src/suit_digest.c
RESULT	= result.txt

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) -o $@ main.c $(SRCS) $(CFLAGS) $(LDFLAGS) $(INC)

run: $(TARGET)
	$(TARGET) | tee $(RESULT)
	$(eval RES := $(shell cat $(RESULT) | head -n-2 | tail -n+4 | awk '{print $$5}' | paste -s | sed 's/\t//g'))
	exit $(RES)

clean:
	$(RM) $(TARGET) $(RESULT)
