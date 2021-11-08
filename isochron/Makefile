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

TARGET := isochron/isochron

all: $(TARGET)

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

install: isochron/isochron
	install -m 0755 -D isochron/isochron $(DESTDIR)${bindir}/isochron
