CC = zig cc
CFLAGS = -target wasm32-freestanding -O2 -gline-tables-only -nostdlib -Wl,--no-entry

all: $(patsubst %.c,%.wasm,$(wildcard */*.c))

%.wasm: %.c
	cd $(dir $<) && $(CC) $(CFLAGS) -fdebug-prefix-map=$$PWD=. -o $(notdir $@) $(notdir $<)

.PHONY: all
