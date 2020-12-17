VERSION := $(shell ./setlocalversion)
CFLAGS := $(CFLAGS) -DVERSION=\"${VERSION}\"

include isochron/Makefile
