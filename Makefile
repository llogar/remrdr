PCSC_CFLAGS := $(shell pkg-config --cflags libpcsclite)

CFLAGS += -c -Wall -Werror -fPIC $(PCSC_CFLAGS)

libremrdr.so: remrdr.o
	$(CC) -shared -o libremrdr.so remrdr.o

remrdr.o: remrdr.c
	$(CC) $(CFLAGS) -o remrdr.o remrdr.c

install:
	sudo install -dv -m755 $(DESTDIR)/etc/reader.conf.d
	sudo install -m644 -o root -g root remrdr.conf $(DESTDIR)/etc/reader.conf.d/remrdr
	sudo install -dv -m755 $(DESTDIR)/usr/lib/
	sudo install -m644 -o root -g root libremrdr.so $(DESTDIR)/usr/lib

clean:
	rm -f libremrdr.so remrdr.o
