TARGET := pov
CC ?= gcc
CPPFLAGS ?=
CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow
LDFLAGS ?= -static

.PHONY: all clean

all: $(TARGET)

$(TARGET): pov.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

clean:
	$(RM) $(TARGET)
