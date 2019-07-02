raw-l2-rcv: raw-l2-rcv.o common.o
	$(CC) $^ -o $@ $(LDFLAGS)

raw-l2-send: raw-l2-send.o common.o
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f raw-l2-rcv.o raw-l2-send.o common.o
