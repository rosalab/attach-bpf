.PHONY all: inliner entry exit

inliner: inliner.c
	gcc -g inliner.c -lelf -o inliner

entry: entry.c
	gcc -c -O0 entry.c -o entry

exit: exit.c
	gcc -c -O0 exit.c -o exit

