CC=gcc
CFLAGS = -Wall -std=c99 -I../inc -g
LDFLAGS = -L../lib -lhbeaconservice -ljson-c  -lcurl

SRCS = main.c
OBJS = main.o
TARGET = test

.PHONY: all
all: $(TARGET)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
