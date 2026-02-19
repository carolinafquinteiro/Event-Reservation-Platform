# Makefile for RC Project

# Compiler flags
CC = gcc
CFLAGS = -Wall -Wextra -g

# Targets
all: ESI user

# Compile Server (ES)
# Links server.c, udp_server.c, and tcp_server.c into a single executable 'ES'
ESI: server.o udp_server.o tcp_server.o auxiliary.o
	$(CC) $(CFLAGS) -o ES server.o udp_server.o tcp_server.o auxiliary.o

# Compile Client (user)
# Links client.c into executable 'user'
user: client.o auxiliary.o
	$(CC) $(CFLAGS) -o user client.o auxiliary.o

# Dependencies (compiling .c to .o)
server.o: server.c auxiliary.h constants.h
	$(CC) $(CFLAGS) -c server.c

udp_server.o: udp_server.c auxiliary.h constants.h
	$(CC) $(CFLAGS) -c udp_server.c

tcp_server.o: tcp_server.c auxiliary.h constants.h
	$(CC) $(CFLAGS) -c tcp_server.c

client.o: client.c client.h  auxiliary.h constants.h
	$(CC) $(CFLAGS) -c client.c

auxiliary.o: auxiliary.c auxiliary.h constants.h
	$(CC) $(CFLAGS) -c auxiliary.c

# Clean up
clean:
	rm -f *.o ES user
# rm -rf ESDIR 