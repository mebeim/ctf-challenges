#
# @mebeim - 2025-06-10
#

SOLVER_BINARY := solve
SOLVER_SRC    := solve.c

CC := gcc
CFLAGS := -Os -s -std=gnu99 -Wall -Wextra -Wno-unused-parameter -static-pie

MAKEFLAGS += --silent

$(SOLVER_BINARY): $(SOLVER_SRC)
	echo 'CCLD    $@'
	$(CC) $(CFLAGS) -o $@ $^

clean:
	echo 'CLEAN   $(SOLVER_BINARY)'
	rm -f '$(SOLVER_BINARY)'
.PHONY: clean
