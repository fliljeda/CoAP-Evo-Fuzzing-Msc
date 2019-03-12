CC=g++

all: main.o

main.o: main.cpp
	$(CC) main.cpp -o main.o

silent: main.cpp
	@$(CC) main.cpp -o main.o

runcov: main.o
	@./main.o "cov.o"

run: main.o
	@./main.o $(MYARGS)
