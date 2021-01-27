PKG_NAME=node-pmvl

SRCDIR = src
OBJDIR = obj
BINDIR = bin
INCDIR = include

BINNAME = $(BINDIR)/$(PKG_NAME)

LDFLAGS += -Wl,-Bstatic -ljson-c-parser -lsaferjson
LDFLAGS += -Wl,-Bdynamic -ljson-c -levent -levtssl -lssl -lcrypto

CFLAGS += -I$(INCDIR) -Wall -Wpedantic -Wextra -pedantic -std=gnu99

ifeq (1,$(DEBUG))
CFLAGS += -g
else
CFLAGS += -O2
endif

SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))


.PHONY: default clean

default: $(BINNAME)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINNAME): $(OBJECTS) | $(BINDIR)
	$(CC) -o $(BINNAME) $^ $(LDFLAGS)

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) -c $< -o $@ $(CFLAGS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(BINDIR) $(OBJDIR)
