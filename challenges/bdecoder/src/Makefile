#
# @mebeim - 2024-09-13
#
SRCDIR := src
OUTDIR := build
SRCS   := $(wildcard $(SRCDIR)/*.c)
OBJS   := $(patsubst $(SRCDIR)/%.c,$(OUTDIR)/%.o,$(SRCS))
DEPS   := $(OBJS:.o=.d)

CHALL_NAME  := bdecoder
BINARY      := $(OUTDIR)/$(CHALL_NAME)
ARCHIVE_DIR := $(CHALL_NAME)
ARCHIVE     := $(CHALL_NAME).tar.gz

CC := aarch64-linux-gnu-gcc

CFLAGS := -O0 -std=gnu99 -MMD -Wall -Wextra \
	-static -no-pie -fno-pie -fno-asynchronous-unwind-tables \
	-fno-stack-protector -march=armv8.3-a -mbranch-protection=pac-ret \
	-Isrc

ifeq ($(DEBUG),1)
	CFLAGS += -g
endif

MAKEFLAGS += --silent
.DEFAULT_GOAL := $(BINARY)

-include $(DEPS)

$(BINARY): ./check_insns.py $(OBJS) | $(OUTDIR)
	echo 'CCLD    $@'
	$(CC) $(CFLAGS) -o $@ $(filter-out $<,$^)
	echo 'CHECK   $@'
	./$< $@


$(OUTDIR)/%.o: $(SRCDIR)/%.c | $(OUTDIR)
	echo 'CC      $@'
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR):
	echo 'MKDIR   $@'
	mkdir -p $@

clean:
	echo 'CLEAN   $(OUTDIR)'
	rm -fr '$(OUTDIR)'
.PHONY: clean

archive: $(ARCHIVE)

$(ARCHIVE): $(BINARY) qemu-9.1.0.patch docker-compose.yml Dockerfile PLAYER_README.md
	echo 'ARCHIVE $@'
	mkdir -p $(ARCHIVE_DIR)
	cp $(BINARY) qemu-9.1.0.patch Dockerfile $(ARCHIVE_DIR)
	cp PLAYER_README.md $(ARCHIVE_DIR)/README.md
	sed -e 's|./build/bdecoder:/home/user/bdecoder:ro|./bdecoder:/home/user/bdecoder:ro|' \
		-e 's/FLAG=ECSC{[^}]\+}/FLAG=ECSC{redacted}/' \
		-e 's/TIMEOUT=[[:digit:]]\+/TIMEOUT=9999/' \
		-e '/POW_BYPASS_HASH=/d' \
		-e '/POW_BITS=/d' \
		docker-compose.yml > $(ARCHIVE_DIR)/docker-compose.yml
	tar czf $(ARCHIVE) $(ARCHIVE_DIR)
	rm -rf $(ARCHIVE_DIR)
