prefix ?= /usr/local
exec_prefix ?= ${prefix}
bindir ?= ${exec_prefix}/bin

src := \
	argparser.o \
	common.o \
	isochron.o \
	log.o \
	management.o \
	ptpmon.o \
	rcv.o \
	report.o \
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

TARGET := isochron/isochron

isochron: $(TARGET)

man: $(manpages)

pdf: $(pdf_docs)

all: isochron man pdf

docs/man/%: docs/%.md
	pandoc --standalone --to man $^ -o $@

docs/pdf/%.pdf: docs/%.md
	pandoc --standalone -t latex $^ -o $@

# include all .d files
-include $(deps)

isochron/isochron: $(objs)
	$(CC) $^ -o $@ $(LDFLAGS) -lm

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@
ifeq ($(C),1)
	$(CHECK) $(CHECKFLAGS) $(CFLAGS) $<
endif

clean:
	rm -f $(objs) $(deps) $(TARGET)
	rm -f docs/pdf/* docs/man/*

install: install-binaries install-manpages

install-manpages: $(manpages)
	$(foreach manpage, $^, install -m 0644 -D $(manpage) \
		$(call get_manpage_destination,$(manpage));)

install-binaries: $(TARGET)
	install -m 0755 -D $(TARGET) $(DESTDIR)${bindir}/isochron

install: install-binaries install-manpages
