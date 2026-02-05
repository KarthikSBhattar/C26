# C26 Compiler Makefile

CC = clang
LLVM_CONFIG = /opt/homebrew/opt/llvm/bin/llvm-config
CFLAGS = -Wall -Wextra -std=c11 -g $(shell $(LLVM_CONFIG) --cflags) -I/opt/homebrew/opt/bdw-gc/include
LDFLAGS = -L/opt/homebrew/opt/llvm/lib -lLLVM -L/opt/homebrew/opt/bdw-gc/lib -lgc

SRCDIR = src
BUILDDIR = build

SOURCES = $(SRCDIR)/main.c $(SRCDIR)/lexer.c $(SRCDIR)/parser.c $(SRCDIR)/codegen.c
OBJECTS = $(BUILDDIR)/main.o $(BUILDDIR)/lexer.o $(BUILDDIR)/parser.o $(BUILDDIR)/codegen.o
TARGET = c26c

.PHONY: all clean test

all: $(BUILDDIR) $(TARGET)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILDDIR) $(TARGET) *.o

test: $(TARGET)
	./$(TARGET) examples/minimal.c26 -o minimal
	./minimal; echo "Exit code: $$?"
