all: inliner entry exit main inliner2

inliner: inliner.c
	gcc -L udis86/libudis86 -I udis86/ -g inliner.c -lelf -llibudis86 -o inliner

inliner2: inliner2.c
	gcc -fpatchable-function-entry=5 -L  udis86/libudis86 -I udis86/ -g inliner2.c -lelf -llibudis86 -o inliner2

entry: entry.c
	gcc -c -O0 entry.c -o entry-elf
	objcopy -O binary --only-section=.text entry-elf entry

exit: exit.c
	gcc -c -O0 exit.c -o exit-elf
	objcopy -O binary --only-section=.text exit-elf exit

main: main.c
	gcc -g -O0 main.c -o main-elf
	objcopy -O binary --only-section=.text main-elf main
