all: raw-l2-send raw-l2-rcv

raw-l2-rcv: isochron/rcv.o isochron/common.o
	$(CC) $^ -o $@ $(LDFLAGS)

raw-l2-send: isochron/send.o isochron/common.o
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f isochron/rcv.o isochron/send.o isochron/common.o raw-l2-rcv raw-l2-send
