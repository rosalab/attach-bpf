all: inliner entry exit main

inliner: inliner.c
	gcc -g inliner.c -lelf -o inliner

entry: entry.c
	gcc -c -O0 entry.c -o entry-elf
	objcopy -O binary --only-section=.text entry-elf entry

exit: exit.c
	gcc -c -O0 exit.c -o exit-elf
	objcopy -O binary --only-section=.text exit-elf exit

main: main.c
	gcc -c -O0 main.c -o main-elf
	objcopy -O binary --only-section=.text main-elf main
