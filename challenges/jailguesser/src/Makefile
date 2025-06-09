#
# @mebeim - 2024-09-18
#

CHALL_NAME    := jailguesser
ARCHIVE_DIR   := $(CHALL_NAME)
ARCHIVE       := $(CHALL_NAME).tar.gz
SOLVER_BINARY := solve
SOLVER_SRC    := solve.c

CC := gcc
CFLAGS := -Os -s -std=gnu99 -Wall -Wextra -Wno-unused-parameter -static-pie

MAKEFLAGS += --silent

archive: $(ARCHIVE)
.PHONY: archive

clean:
	echo 'CLEAN   $(SOLVER_BINARY)'
	rm -f '$(SOLVER_BINARY)'
.PHONY: clean

# This also strips line comments from jailguesser.sh and jailguesser.py scripts
# IFF the '#' is followed by whitespace or newline.
$(ARCHIVE): jailguesser.py jailguesser.sh docker-compose.yml Dockerfile
	echo 'ARCHIVE $@'
	mkdir -p $(ARCHIVE_DIR)
	cp $^ $(ARCHIVE_DIR)
	sed -i -e 's/FLAG=ECSC{[^}]\+}/FLAG=ECSC{redacted}/' $(ARCHIVE_DIR)/docker-compose.yml
	sed -i -e '/^\s*#\(\s\|$$\)/d' $(ARCHIVE_DIR)/jailguesser.py
	sed -i -e '/^\s*#\(\s\|$$\)/d' $(ARCHIVE_DIR)/jailguesser.sh
	! grep -qR mebeim $(ARCHIVE_DIR)
	tar czf $(ARCHIVE) $(ARCHIVE_DIR)
	rm -rf $(ARCHIVE_DIR)
