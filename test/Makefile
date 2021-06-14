CFLAGS	= -Wall
LDFLAGS	= -lt_cose -lqcbor -lcrypto -lcunit #-lcsuit
INC		= -I ../inc
SRCS	= ../src/suit_common.c ../src/suit_manifest_process.c ../src/suit_manifest_decode.c ../src/suit_manifest_encode.c ../src/suit_manifest_print.c ../src/suit_cose.c ../src/suit_digest.c

all:
	$(CC) main.c $(SRCS) $(CFLAGS) $(LDFLAGS) $(INC)

