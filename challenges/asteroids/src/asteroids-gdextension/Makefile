#
# @mebeim - 2025-09-07
#

PLATFORM := linux
TARGET := template_debug

.DEFAULT_GOAL: all

all: generated
	scons platform=$(PLATFORM) target=$(TARGET)
.PHONY: all

clean:
	scons platform=$(PLATFORM) target=$(TARGET) --clean
.PHONY: clean

# Python generated achievement parameters and code. Can't be bothered to make this nicer.
generated: gen_achievements.py
	./$<
.PHONY: generated
