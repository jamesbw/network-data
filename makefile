
CFLAGS	= -g -Wall
CC	= gcc
CCF	= $(CC) $(CFLAGS)




all:	pcap_parse

pcap_parse:	pcap_parse.c
	$(CCF) pcap_parse.c -L. -lpcap -o pcap_parse  -Ilibpcap-1.1.1/

clean:
	rm -f pcap_parse *.o

