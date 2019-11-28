CC=gcc
WARNINGS=-Wall -pedantic -Wno-unused-function
CFLAGS=$(WARNINGS) -c -I. -g
SOURCES=$(wildcard *.c)
OBJDIR=obj
OBJECTS=$(patsubst %.c,$(OBJDIR)/%.o, $(SOURCES))
BINDIR=bin
EXEC=program

all: $(BINDIR)/$(EXEC)

objects:
	mkdir -p obj

clean:
	rm -f $(OBJECTS)

$(BINDIR)/$(EXEC): $(OBJECTS)
	$(CC) $(LFLAGS) -o $@ $^

$(OBJDIR)/%.o: %.c objects
	$(CC) $(CFLAGS) $< -o $@

.PHONY: all clean debug
