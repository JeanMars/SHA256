CROSS=m68k-atari-mint-

CC=$(CROSS)gcc
FLAGS = -O3 -Wall -fomit-frame-pointer
CC000 = $(CC) -m68000 $(FLAGS)
CC020 = $(CC) -m68020 $(FLAGS)
CC_CF = $(CC) -mcfv4e $(FLAGS)
BIN = bin/gcc/
all: $(BIN)sha2.ttp $(BIN)sha220.ttp $(BIN)sha2cf.ttp

$(BIN)sha2.ttp: obj/000/sh2.o obj/000/main.o
	$(CC000) -o $@ $^

obj/000/sh2.o: sh2.c
	$(CC000) -c -o $@ $^

obj/000/main.o: main.c
	$(CC000) -c -o $@ $^

$(BIN)sha220.ttp: obj/020/sh2.o obj/020/main.o
	$(CC020) -o $@ $^

obj/020/sh2.o: sh2.c
	$(CC020) -c -o $@ $^

obj/020/main.o: main.c
	$(CC020) -c -o $@ $^

$(BIN)sha2cf.ttp: obj/5475/sh2.o obj/5475/main.o
	$(CC_CF) -o $@ $^

obj/5475/sh2.o: sh2.c
	$(CC_CF) -c -o $@ $^

obj/5475/main.o: main.c
	$(CC_CF) -c -o $@ $^

clean:
	$(RM) obj/000/*.o $(BIN)sha2.ttp obj/020/*.o $(BIN)sha220.ttp /obj/5475/*.o $(BIN)sha2cf.ttp
