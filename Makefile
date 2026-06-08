CC     = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
TARGET = detector

all: $(TARGET)

$(TARGET): detector.c
	$(CC) $(CFLAGS) -o $@ $<

debug: CFLAGS += -O0 -DDEBUG
debug: $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all debug clean
