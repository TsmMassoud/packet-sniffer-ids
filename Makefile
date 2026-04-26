CC = gcc
CFLAGS = -Wall -g
INCLUDES = -Iinclude
LIBS = -lpcap

# File list
SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:src/%.c=obj/%.o)
TARGET = bin/my_prog

# Default rule
all: $(TARGET)

# Linking rule to create the executable
$(TARGET): $(OBJS)
	@mkdir -p bin
	@echo "Linking binary : $@"
	@$(CC) $(OBJS) -o $(TARGET) $(LIBS)

# Compilation rule for object files
obj/%.o: src/%.c
	@mkdir -p obj
	@echo "File compiled : $<"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean up generated files
clean:
	@echo "Cleaning..."
	@rm -rf obj bin

.PHONY: all clean