.PHONY: all

all: run

bench: main.c
	gcc main.c -o bench

run: bench
	./bench
