VERSION := $(shell ./setlocalversion)
EXTRA_CFLAGS := $(shell ./toolchain_deps.sh "$(CC)" "$(CFLAGS)")
CFLAGS := $(CFLAGS) -DVERSION=\"${VERSION}\" $(EXTRA_CFLAGS)
CFLAGS += -Wall -Wextra -Werror -Wno-error=sign-compare

include isochron/Makefile
