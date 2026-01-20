# Run this inside Alpine container!

SRCDIR := src
OUTDIR := build
BINARY := $(OUTDIR)/broken-telemetry

ARCHIVE_DIR := broken-telemetry
ARCHIVE     := broken-telemetry.tar.gz

CSRCS := $(wildcard $(SRCDIR)/*.c)
ASRCS := $(wildcard $(SRCDIR)/*.S)
OBJS  := $(patsubst $(SRCDIR)/%.c,$(OUTDIR)/%.o,$(CSRCS))
OBJS  += $(patsubst $(SRCDIR)/%.S,$(OUTDIR)/%.o,$(ASRCS))
DEPS  := $(OBJS:.o=.d)

KEYPAIR := $(OUTDIR)/pubkey.bin $(OUTDIR)/privkey.pem
PLAYER_PUBKEY := $(OUTDIR)/player_pubkey.bin
PLAYER_PRIVKEY := $(OUTDIR)/player_privkey.pem
PLAYER_KEYPAIR := $(PLAYER_PUBKEY) $(PLAYER_PRIVKEY)

CC      := gcc
CFLAGS  := -Wall -Wextra -MMD -std=gnu11 -fno-strict-aliasing -fPIE
LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack
LDLIBS  := -lpthread -lcrypto

ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG
else
	LDFLAGS += -s
endif

.DEFAULT_GOAL := all
-include $(DEPS)

.PHONY: all archive clean

all: $(BINARY) $(KEYPAIR) $(PLAYER_KEYPAIR)

archive: $(ARCHIVE)

$(BINARY): $(OBJS) | $(OUTDIR)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OUTDIR)/%.o: $(SRCDIR)/%.c | $(OUTDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR)/%.o: $(SRCDIR)/%.S | $(OUTDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(KEYPAIR) $(PLAYER_KEYPAIR): ./genkey.py | $(OUTDIR)
	./genkey.py

$(ARCHIVE): $(BINARY) $(PLAYER_KEYPAIR) Dockerfile.player test/telemetry.bin PLAYER_README.md
	rm -rf $(ARCHIVE_DIR)
	mkdir $(ARCHIVE_DIR)

	cp $(BINARY) $(ARCHIVE_DIR)/
	cp Dockerfile.player $(ARCHIVE_DIR)/Dockerfile
	cp PLAYER_README.md $(ARCHIVE_DIR)/README.md
	cp test/telemetry.bin $(ARCHIVE_DIR)/
	cp $(PLAYER_PUBKEY) $(ARCHIVE_DIR)/pubkey.bin
	cp $(PLAYER_PRIVKEY) $(ARCHIVE_DIR)/privkey.pem
	
	tar czf $@ $(ARCHIVE_DIR)

	rm -rf $(ARCHIVE_DIR)

$(OUTDIR):
	mkdir -p $@

clean:
	rm -fr $(OUTDIR)
