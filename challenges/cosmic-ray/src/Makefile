#
# @mebeim - 2025-08-28
#

ARCHIVE        := cosmic-ray.tar.gz
ARCHIVE_TOPDIR := cosmic-ray

ifneq ($(V),1)
MAKEFLAGS += --silent
endif

.DEFAULT_GOAL := archive

archive: $(ARCHIVE)
.PHONY: archive

$(ARCHIVE): app.py Dockerfile docker-compose.yml | $(ARCHIVE_TOPDIR)
	echo 'ARCHIVE $@'

	cp app.py Dockerfile docker-compose.yml $(ARCHIVE_TOPDIR)
# Remove source code comments
	sed -i -e '/^\s*#\(\s\|$$\)/d' $(ARCHIVE_TOPDIR)/app.py
# Redact flag
	sed -i -e 's/space{[^}]\+}/space{REDACTED}/' $(ARCHIVE_TOPDIR)/Dockerfile

	tar -czf $@ $(ARCHIVE_TOPDIR)
	rm -rf $(ARCHIVE_TOPDIR)

$(ARCHIVE_TOPDIR):
	echo 'MKDIR   $@'
	mkdir -p $@

clean:
	echo 'CLEAN'
	rm -f '$(ARCHIVE)'
	rm -fr '$(ARCHIVE_TOPDIR)'
.PHONY: clean
