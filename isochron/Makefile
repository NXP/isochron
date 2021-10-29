prefix ?= /usr/local
exec_prefix ?= ${prefix}
bindir ?= ${exec_prefix}/bin

src := \
	isochron.o \
	common.o \
	rcv.o \
	ptpmon.o \
	send.o \
	stats.o

objs := $(addprefix isochron/, $(src))

isochron/isochron: $(objs)
	$(CC) $^ -o $@ $(LDFLAGS) -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f $(objs)

install: isochron/isochron
	install -m 0755 -D isochron/isochron $(DESTDIR)${bindir}/isochron
