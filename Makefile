all: raw-l2-send raw-l2-rcv

raw-l2-rcv: raw-l2-rcv.o raw-l2-common.o
	$(CC) $^ -o $@ $(LDFLAGS)

raw-l2-send: raw-l2-send.o raw-l2-common.o
	$(CC) $^ -o $@ $(LDFLAGS)

8021qbv.zip: $(wildcard deps/*) common.sh Makefile raw-l2-common.c raw-l2-rcv raw-l2-rcv.c raw-l2-send raw-l2-send.c time-test.awk time-test.sh README.8021qbv.txt
	zip $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f raw-l2-rcv.o raw-l2-send.o raw-l2-common.o raw-l2-rcv raw-l2-send
