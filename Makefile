VERSION := $(shell ./setlocalversion)
MY_CPPFLAGS := -DVERSION=\"${VERSION}\" $(CPPFLAGS)
MY_CPPFLAGS += $(shell ./toolchain_deps.sh "$(CC)" "$(MY_CPPFLAGS)")
MY_CFLAGS := -Wall -Wextra -Werror -Wno-error=sign-compare \
	     -Wno-error=missing-field-initializers \
	     -Wno-unused-parameter $(CFLAGS)
MY_LDFLAGS := $(LDFLAGS)
CHECK := sparse
CHECKFLAGS := -D__linux__ -Dlinux -D__STDC__ -Dunix -D__unix__ \
	      -Wbitwise -Wno-return-void -Wno-unknown-attribute $(CF)

ifeq ($(C),1)
REAL_CC := $(CC)
CC := cgcc
export REAL_CC
endif

prefix ?= /usr/local
exec_prefix ?= ${prefix}
bindir ?= ${exec_prefix}/bin
datarootdir ?= ${prefix}/share
mandir ?= ${datarootdir}/man
PKG_CONFIG ?= pkg-config
INSTALL ?= install

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
	sk.o \
	syncmon.o \
	sysmon.o

symlinks := \
	isochron-daemon \
	isochron-orchestrate \
	isochron-send \
	isochron-rcv \
	isochron-report

objs := $(addprefix src/, $(src))
deps := $(patsubst %.o, %.d, $(objs))

md_docs  := $(wildcard docs/*.md)
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
MY_LDFLAGS += $(LIBMNL_LDFLAGS)

TARGET := isochron

all: $(TARGET) man

man: $(manpages)

docs/man/%: docs/%.md
	@mkdir -p $(@D)
	pandoc --standalone --to man $^ -o $@

# include all .d files
-include $(deps)

$(TARGET): $(objs)
	$(CC) $^ -o $@ $(MY_LDFLAGS) -lm -pthread

%.o: %.c
	$(CC) $(MY_CPPFLAGS) $(MY_CFLAGS) -MMD -c $< -o $@
ifeq ($(C),1)
	$(CHECK) $(CHECKFLAGS) $(MY_CPPFLAGS) $(MY_CFLAGS) $<
endif

clean:
	rm -f $(objs) $(deps) $(TARGET)
	rm -f docs/man/*

install-manpages: $(manpages)
	$(foreach manpage, $^, $(INSTALL) -m 0644 -D $(manpage) \
		$(call get_manpage_destination,$(manpage));)

install-binaries: $(TARGET)
	$(INSTALL) -m 0755 -D $(TARGET) $(DESTDIR)${bindir}/isochron
	$(foreach symlink, $(symlinks), \
		ln -sf $(TARGET) $(DESTDIR)${bindir}/$(symlink);)

install-completion: bash-completion/isochron
	$(INSTALL) -m 0644 -D $< $(DESTDIR)${datarootdir}/bash-completion/completions/isochron
	$(foreach symlink, $(symlinks), \
		ln -sf $(TARGET) $(DESTDIR)${datarootdir}/bash-completion/completions/$(symlink);)

install: install-binaries install-manpages install-completion
