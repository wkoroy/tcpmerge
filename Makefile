APP = ./tcpmerge
CC=gcc -g -O0
CFLAGS=  -static -ldl -lrt -lpthread -Wall -Wextra

all: $(APP)
 


$(APPTEST): tcpmerge.o  pcap_file_generator.o pcap_file_reader.o utils.o
	$(CC) tcpmerge.o pcap_file_generator.o pcap_file_reader.o utils.o -o $(APP) $(CFLAGS) -D TCPMERGE_TEST
$(APP): tcpmerge.o  pcap_file_generator.o pcap_file_reader.o utils.o
	$(CC) tcpmerge.o pcap_file_generator.o pcap_file_reader.o utils.o -o $(APP) $(CFLAGS)
tcpmerge.o: tcpmerge.c	
	$(CC) tcpmerge.c -c -Wall

pcap_file_generator.o: pcap_file_generator.c	
	$(CC) pcap_file_generator.c -c -Wall

pcap_file_reader.o: pcap_file_reader.c
	$(CC) pcap_file_reader.c -c -Wall

utils.o: utils.c
	$(CC) utils.c -c -Wall
clean:
	rm -f *.o ; rm $(APP);rm -f *~;
test: $(APPTEST)
