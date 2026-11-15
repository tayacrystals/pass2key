NAME	?= pass2key
CC      ?= cc
CPPFLAGS += -Ivendor/monocypher
# Optimization stays overridable (environment CFLAGS or `make CFLAGS=...`),
# but the dialect, warning and include flags are appended unconditionally so
# they cannot be lost by accident. Note that CFLAGS given on the make command
# line replaces all of these; add -Isrc -Ivendor/monocypher yourself then.
CFLAGS  += -std=c99 -Wall -Wextra -Wpedantic -Isrc
CFLAGS  ?= -O2
LDFLAGS ?=

SRC_DIR := src
BUILD   := build
BIN     := $(BUILD)/$(NAME)
VECTORS ?= vectors

SRCS := $(wildcard $(SRC_DIR)/*.c) $(wildcard vendor/monocypher/*.c)
OBJS := $(SRCS:%.c=$(BUILD)/%.o)

# Everything but main(), for linking the test programs.
CORE_SRCS := $(filter-out $(SRC_DIR)/main.c,$(SRCS))
TESTS := $(BUILD)/test_input $(BUILD)/test_packet_length \
         $(BUILD)/test_openpgp $(BUILD)/test_e2e

.PHONY: all clean run check check-slow check-vendor

all: $(BIN)

$(BIN): $(OBJS) | $(BUILD)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

$(BUILD)/%.o: %.c | $(BUILD)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

# Unit and vector tests. No Argon2 derivation: seconds, not minutes.
check: $(BIN) $(TESTS)
	$(BUILD)/test_input
	$(BUILD)/test_packet_length
	$(BUILD)/test_openpgp
	$(BUILD)/test_e2e $(VECTORS)
	$(BIN) --selftest
	sh tests/test_cli.sh $(BIN)
	python3 tests/test_interactive.py $(BIN)
	sh tests/check_vendor.sh
	python3 tests/extract_seed.py $(VECTORS)/e2e-test-example.org.asc >/dev/null
	@echo "pass2key: all tests passed"

# Full production derivation, twice (4 GiB and several minutes per run).
check-slow: $(BIN)
	sh tests/test_mismatch.sh $(BIN) $(VECTORS)

check-vendor:
	sh tests/check_vendor.sh

$(BUILD)/test_%: tests/test_%.c $(CORE_SRCS) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(CORE_SRCS) $<

run: $(BIN)
	./$(BIN)

clean:
	rm -rf $(BUILD)

-include $(OBJS:.o=.d)
