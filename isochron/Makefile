isochron: isochron.o common.o rcv.o send.o
	$(CC) $^ -o $@ $(LDFLAGS) -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f isochron.o rcv.o send.o common.o isochron
