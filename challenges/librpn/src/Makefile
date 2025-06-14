#
# @mebeim - 2025-06-07
#
LIBRPN_SO  := librpn.so
LIBRPN_C   := librpn.c

ARCHIVE        := librpn.tar.gz
ARCHIVE_TOPDIR := librpn

CC      := musl-gcc
CFLAGS  := -std=gnu11 -Wall -Wextra -fPIC -s
LDFLAGS := -shared

ifneq ($(V),1)
MAKEFLAGS += --silent
endif

.DEFAULT_GOAL := $(BINARY)

$(LIBRPN_SO): $(LIBRPN_C)
	echo 'CCLD    $@'
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

archive: $(ARCHIVE)
.PHONY: archive

$(ARCHIVE): $(LIBRPN_SO) calculator.py docker-compose.yml | $(ARCHIVE_TOPDIR)
	echo 'ARCHIVE $(ARCHIVE)'
	mkdir -p $(ARCHIVE_TOPDIR)

	cp $(LIBRPN_SO) calculator.py $(ARCHIVE_TOPDIR)

	sed -e 's/TIMEOUT=[[:digit:]]\+/TIMEOUT=9999/' \
		-e 's/FLAG=[^}]\+}/FLAG=TEC{redacted}/' \
		docker-compose.yml > $(ARCHIVE_TOPDIR)/docker-compose.yml

	tar -czf $(ARCHIVE) $(ARCHIVE_TOPDIR)
	rm -rf $(ARCHIVE_TOPDIR)

$(ARCHIVE_TOPDIR):
	echo 'MKDIR   $@'
	mkdir -p $@

clean:
	echo 'CLEAN'
	rm -f '$(LIBRPN_SO)' '$(ARCHIVE)'
	rm -fr '$(ARCHIVE_TOPDIR)'
.PHONY: clean
