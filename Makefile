NAME	?= pass2key
CC      ?= cc
CPPFLAGS += -Ivendor/monocypher
CFLAGS  ?= -std=c99 -Wall -Wextra -Wpedantic
CFLAGS  += -O2
LDFLAGS ?=

SRC_DIR := src
BUILD   := build
BIN     := $(BUILD)/$(NAME)

SRCS := $(wildcard $(SRC_DIR)/*.c) $(wildcard vendor/monocypher/*.c)
OBJS := $(SRCS:%.c=$(BUILD)/%.o)

.PHONY: all clean run

all: $(BIN)

$(BIN): $(OBJS) | $(BUILD)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

$(BUILD)/%.o: %.c | $(BUILD)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

run: $(BIN)
	./$(BIN)

clean:
	rm -rf $(BUILD)

-include $(OBJS:.o=.d)
