CC := aarch64-linux-gnu-gcc
CFLAGS := -shared -fPIC -nostartfiles

.PHONY: all clean

all: module.so

module.so: module.c redismodule.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f module.so
