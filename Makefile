CC = gcc
CFLAGS = -g

LIB=lib
SRC=src
BIN=bin
TEST_SRC=test-cases
INC=include
LIB_OBJ=lib
OBJ=obj
BENCH_SRC=benchmark-test
BENCH_OBJ=bech-obj


# src = $(wildcard Examples/*.c)

# obj = $(src:.c=.o)

HDRS=$(shell ls $(INC)/*.h)

all: bin/crp

bin/crp: $(OBJ)/crp.o
	mkdir -p bin
	$(CC) -o $@ $<

$(OBJ)/%.o: $(SRC)/%.c $(HDRS)
	mkdir -p obj
	$(CC) -c -I$(INC) $< -o $@

.PHONY: clean
clean:
	rm -rf $(OBJ) $(LIB) $(BENCH_OBJ)
