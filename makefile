
CFLAGS	= -g -Wall
CC	= gcc
CCF	= $(CC) $(CFLAGS)




all:	pcap_parse

pcap_parse:	pcap_parse.c
	$(CCF) pcap_parse.c  -lpcap -o pcap_parse

clean:
	rm -f pcap_parse *.o

