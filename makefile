all:
	gcc read_pcap.c -o read_pcap -lpcap
clean:
	rm read_pcap
