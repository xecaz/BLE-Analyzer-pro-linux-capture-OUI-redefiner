PREFIX ?= /usr/local
CC = gcc
CFLAGS = -O2 -Wall -Wextra

oui_lookup: oui_lookup.c
	$(CC) $(CFLAGS) -o $@ $<

install: oui_lookup
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 oui_lookup $(DESTDIR)$(PREFIX)/bin/oui_lookup

clean:
	rm -f oui_lookup

.PHONY: clean install
