CC     ?= gcc
CFLAGS := -O2 -Wall -Wextra -std=gnu11
LDFLAGS := -static
BIN    := skb_segment_exploit

all: $(BIN)

$(BIN): skb_segment_exploit.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(BIN)

.PHONY: all clean
