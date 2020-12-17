VERSION := $(shell ./setlocalversion --save-scmversion && cat .scmversion)
CFLAGS := $(CFLAGS) -DVERSION=\"${VERSION}\"

include isochron/Makefile
