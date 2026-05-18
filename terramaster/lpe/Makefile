CC := aarch64-linux-gnu-gcc
CFLAGS := -static

all: suid

suid: suid.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f suid
