CC = gcc
CFLAGS = -O2 -Wall -Wextra

oui_lookup: oui_lookup.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f oui_lookup

.PHONY: clean
