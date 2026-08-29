TARGET := trigger
CC ?= gcc
CPPFLAGS ?=
CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow
LDFLAGS ?= -static

.PHONY: all clean

all: $(TARGET)

$(TARGET): trigger.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

clean:
	$(RM) $(TARGET)
