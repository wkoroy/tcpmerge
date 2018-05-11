APP = ./tcpmerge
CC=gcc -g -O0
CFLAGS=  -static -ldl -lrt -lpthread -Wall -Wextra -L./  -lpcap_file_generator

all: $(APP)

$(APPTEST): tcpmerge.o
	$(CC) tcpmerge.o -o $(APP) $(CFLAGS) -D TCPMERGE_TEST
$(APP): tcpmerge.o
	$(CC) tcpmerge.o -o $(APP) $(CFLAGS)
tcpmerge.o: tcpmerge.c	
	$(CC) tcpmerge.c -c -Wall

clean:
	rm -f *.o ; rm $(APP);rm -f *~;
test: $(APPTEST)
