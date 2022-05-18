VERSION := $(shell ./setlocalversion)
MY_CFLAGS := -DVERSION=\"${VERSION}\" $(CFLAGS)
MY_CFLAGS += -Wall -Wextra -Werror -Wno-error=sign-compare
MY_CFLAGS += $(shell ./toolchain_deps.sh "$(CC)" "$(MY_CFLAGS)")
CHECK := sparse
CHECKFLAGS := -D__linux__ -Dlinux -D__STDC__ -Dunix -D__unix__ \
	      -Wbitwise -Wno-return-void -Wno-unknown-attribute $(CF)

ifeq ($(C),1)
REAL_CC := $(CC)
CC := cgcc
export REAL_CC
endif

include isochron/Makefile
