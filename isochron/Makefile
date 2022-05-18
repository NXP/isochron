prefix ?= /usr/local
exec_prefix ?= ${prefix}
bindir ?= ${exec_prefix}/bin
etcdir ?= /etc
datarootdir ?= ${prefix}/share
mandir ?= ${datarootdir}/man
PKG_CONFIG ?= pkg-config

src := \
	argparser.o \
	common.o \
	daemon.o \
	isochron.o \
	log.o \
	management.o \
	orchestrate.o \
	ptpmon.o \
	rcv.o \
	report.o \
	rtnl.o \
	send.o \
	sysmon.o

objs := $(addprefix isochron/, $(src))
deps := $(patsubst %.o, %.d, $(objs))

md_docs  := $(wildcard docs/*.md)
pdf_docs := $(patsubst docs/%.md, docs/pdf/%.pdf, $(md_docs))
manpages := $(patsubst docs/%.md, docs/man/%, $(md_docs))

# Input: path to manpage file from sources
# Output: DESTDIR-prefixed install location
get_man_section = $(lastword $(subst ., ,$1))
get_manpage_destination = $(join $(DESTDIR)${mandir}/man, \
                          $(join $(call get_man_section,$1)/, \
                          $(subst docs/man/,,$1)))

ifeq (, $(shell which $(PKG_CONFIG)))
$(error No pkg-config binary in $(PATH))
endif

LIBMNL_CFLAGS  := $(shell ${PKG_CONFIG} --cflags libmnl)
LIBMNL_LDFLAGS := $(shell ${PKG_CONFIG} --libs libmnl)

ifeq (, $(LIBMNL_CFLAGS)$(LIBMNL_LDFLAGS))
$(error pkg-config could not find libmnl)
endif

MY_CFLAGS += $(LIBMNL_CFLAGS)
LDFLAGS += $(LIBMNL_LDFLAGS)

TARGET := isochron/isochron

all: isochron man pdf

isochron: $(TARGET)

man: $(manpages)

pdf: $(pdf_docs)

docs/man/%: docs/%.md
	@mkdir -p $(@D)
	pandoc --standalone --to man $^ -o $@

docs/pdf/%.pdf: docs/%.md
	@mkdir -p $(@D)
	pandoc --standalone -t latex $^ -o $@

# include all .d files
-include $(deps)

isochron/isochron: $(objs)
	$(CC) $^ -o $@ $(LDFLAGS) -lm -pthread

%.o: %.c
	$(CC) $(MY_CFLAGS) -MMD -c $< -o $@
ifeq ($(C),1)
	$(CHECK) $(CHECKFLAGS) $(MY_CFLAGS) $<
endif

clean:
	rm -f $(objs) $(deps) $(TARGET)
	rm -f docs/pdf/* docs/man/*

install-manpages: $(manpages)
	$(foreach manpage, $^, install -m 0644 -D $(manpage) \
		$(call get_manpage_destination,$(manpage));)

install-binaries: $(TARGET)
	install -m 0755 -D $(TARGET) $(DESTDIR)${bindir}/isochron

install-completion: bash-completion/isochron-completion.bash
	install -m 0755 -D $< $(DESTDIR)$(etcdir)/bash_completion.d/isochron-completion.bash

install: install-binaries install-manpages install-completion
