CC = g++
CFLAGS = -Wall
LDLIBS = -lpcap

all: beacon-flood

beacon-flood: main.cpp
	$(CC) $(CFLAGS) -o beacon-flood main.cpp $(LDLIBS)

clean:
	rm -f beacon-flood