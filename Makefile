.PHONY: all

all: run

bench: main.c
	gcc main.c msgpuck/msgpuck.c msgpuck/hints.c -o bench -Os

run: bench
	./bench
