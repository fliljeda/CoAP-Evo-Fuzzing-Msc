CC=g++
FLAGS=-std=c++17 -Wall -lstdc++fs
SRCS=main.cpp network_handler.cpp packet_handler.cpp coap_mutations.cpp fuzzer.cpp evo_handler.cpp evo_handler.cpp server_handler.cpp logger.cpp printcrash.cpp

all: main.o printcrash.o

main.o: $(SRCS)
	$(CC) main.cpp -o main.o $(FLAGS) 

printcrash.o: $(SRCS)
	$(CC) printcrash.cpp -o printcrash.o $(FLAGS) 

silent: main.cpp
	@$(CC) main.cpp -o main.o $(FLAGS) 

runcov: main.o
	@./main.o "cov.o"

test-packets: $(SRCS) test-packets.cpp
	$(CC) test-packets.cpp -o test-packets.o $(FLAGS) 

run: main.o
	@./main.o $(MYARGS)
