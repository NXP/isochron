isochron: isochron.o common.o rcv.o send.o
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f isochron.o rcv.o send.o common.o isochron
