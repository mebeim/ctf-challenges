SRCDIR  := src
OUTDIR  := build
SRCS    := $(wildcard $(SRCDIR)/*.c)
OBJS    := $(patsubst $(SRCDIR)/%.c,$(OUTDIR)/%.o,$(SRCS))
DEPS    := $(OBJS:.o=.d)
BINARY  := $(OUTDIR)/no-headache

LIBSDIR := $(OUTDIR)/libs
LIBS    := $(LIBSDIR)/ld-linux-x86-64.so.2 $(LIBSDIR)/libc.so.6


ARCHIVE        := no-headache.tar.gz
ARCHIVE_TOPDIR := no-headache

CC     := gcc
CFLAGS := -std=gnu99 -MMD -Wall -Wextra -pedantic -O0

MAKEFLAGS += --silent
.DEFAULT_GOAL := bin-and-libs

-include $(DEPS)


bin-and-libs: $(BINARY) $(LIBS)
.PHONY: bin-and-libs

$(LIBS): $(BINARY) | $(LIBSDIR)
	@echo 'Copying binary libs to $(LIBSDIR)'
	LIBS=$$(ldd $(BINARY) | awk '/vdso/ {next}; /=>/ {print $$3; next}; {print $$1}') \
		&& cp $$LIBS $(LIBSDIR)

$(BINARY): $(OBJS)
	@echo 'CCLD  $@'
	$(CC) $(CFLAGS) -o $@ $^
	@echo 'STRIP $@'
	strip $@

$(OUTDIR)/%.o: $(SRCDIR)/%.c | $(OUTDIR)
	@echo 'CC    $@'
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR) $(LIBSDIR) $(ARCHIVE_TOPDIR):
	@echo 'MKDIR $@'
	mkdir -p $@


archive: $(ARCHIVE)
.PHONY: archive

$(ARCHIVE): $(BINARY) $(LIBS) docker-compose.yml | $(ARCHIVE_TOPDIR)
	@echo 'ARCHIVE $(ARCHIVE)'
	mkdir -p $(ARCHIVE_TOPDIR)/$(OUTDIR)

	cp $(BINARY) $(ARCHIVE_TOPDIR)/$(OUTDIR)
	cp -r $(LIBSDIR) $(ARCHIVE_TOPDIR)/$(OUTDIR)

	sed -e 's/TIMEOUT=[[:digit:]]\+/TIMEOUT=9999/' \
		-e 's/FLAG=[^}]\+}/FLAG=openECSC{redacted}/' \
		docker-compose.yml > $(ARCHIVE_TOPDIR)/docker-compose.yml

	tar -czf $(ARCHIVE) $(ARCHIVE_TOPDIR)
	rm -rf $(ARCHIVE_TOPDIR)


clean:
	@echo 'CLEAN $(OUTDIR) $(ARCHIVE) $(ARCHIVE_TOPDIR)'
	rm -fr '$(OUTDIR)' '$(ARCHIVE)' '$(ARCHIVE_TOPDIR)'
.PHONY: clean
