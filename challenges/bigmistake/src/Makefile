#
# @mebeim - 2025-05-21
#
SRCDIR := src
OUTDIR := build
SRCS   := $(wildcard $(SRCDIR)/*.cc)
OBJS   := $(patsubst $(SRCDIR)/%.cc,$(OUTDIR)/%.o,$(SRCS))
DEPS   := $(OBJS:.o=.d)

CHALL_NAME  := BigMistake
BINARY      := $(OUTDIR)/$(CHALL_NAME)
ARCHIVE_DIR := $(CHALL_NAME)
ARCHIVE     := $(CHALL_NAME).tar.gz

CXX := g++
CXXFLAGS := -std=gnu++11 -g -MMD -Wall -Wextra -Wl,-z,relro,-z,now -I$(SRCDIR)

# Use relative paths as we are embedding debug info
CXXFLAGS += -fdebug-prefix-map=$(shell pwd)=.

MAKEFLAGS += --silent
.DEFAULT_GOAL := $(BINARY)

-include $(DEPS)

$(BINARY): $(OBJS) | $(OUTDIR)
	echo 'CXXLD   $@'
	$(CXX) $(CXXFLAGS) -o $@ $^

$(OUTDIR)/%.o: $(SRCDIR)/%.cc | $(OUTDIR)
	echo 'CXX     $@'
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OUTDIR):
	echo 'MKDIR   $@'
	mkdir -p $@

clean:
	echo 'CLEAN   $(OUTDIR)'
	rm -fr '$(OUTDIR)'
.PHONY: clean

archive: $(ARCHIVE)

$(ARCHIVE): $(BINARY) docker-compose.yml
	echo 'ARCHIVE $@'
	mkdir -p $(ARCHIVE_DIR)
	cp $(BINARY) $(ARCHIVE_DIR)
	sed -e 's|./build/BigMistake:/home/user/chall:ro|./BigMistake:/home/user/chall:ro|' \
		-e 's/FLAG=TeamItaly{[^}]\+}/FLAG=TeamItaly{redacted}/' \
		-e 's/TIMEOUT=[[:digit:]]\+/TIMEOUT=9999/' \
		docker-compose.yml > $(ARCHIVE_DIR)/docker-compose.yml
	tar czf $(ARCHIVE) $(ARCHIVE_DIR)
	rm -rf $(ARCHIVE_DIR)
