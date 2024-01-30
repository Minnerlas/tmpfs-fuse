OBJS = main.o fs.o


CFLAGS = -O3 -g -Wall -Wextra -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE \
		 $$(pkg-config fuse3 --cflags --libs) -DNDEBUG_LOG
		 # -fsanitize=thread -fsanitize=undefined

LDFLAGS = -g $$(pkg-config fuse3 --cflags --libs) # -fsanitize=thread -fsanitize=undefined

OUT = main

all: $(OUT)

run: $(OUT)
	umount mnt; ./$(OUT) -s -f mnt

val: $(OUT)
	umount mnt; valgrind -s --leak-check=full ./$(OUT) -s -d mnt

val: $(OUT)

$(OUT): $(OBJS)
fs.o: fs.c fs.h Makefile
main.o: main.c Makefile

.PHONEY: clean
clean:
	rm -rvf $(OBJS) $(OUT)
