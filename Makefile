.PHONY: all

all: bench

bench: main.c
	gcc main.c -o bench -Os

run: bench
	./bench
