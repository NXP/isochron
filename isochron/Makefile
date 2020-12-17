src := \
	isochron.o \
	common.o \
	rcv.o \
	send.o

objs := $(addprefix isochron/, $(src))

isochron/isochron: $(objs)
	$(CC) $^ -o $@ $(LDFLAGS) -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f $(objs)
