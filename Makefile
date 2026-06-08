CC     = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_GNU_SOURCE -g
TARGET = detector
SRCS   = main.c log.c proc.c elfcheck.c scanner.c monitor.c
OBJS   = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
