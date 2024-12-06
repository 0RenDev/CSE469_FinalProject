# Makefile for bchoc executable

# Compiler
PYTHON := python3

# Executable name
EXECUTABLE := bchoc

# Default target
all: $(EXECUTABLE)

# Build the executable
$(EXECUTABLE): bchoc.py
	echo '#!/usr/bin/env $(PYTHON)' > $(EXECUTABLE)
	cat bchoc.py >> $(EXECUTABLE)
	chmod +x $(EXECUTABLE)

# Clean up
clean:
	rm -f $(EXECUTABLE)

# Ensure compatibility with Unix systems (useful if developed on Windows)
fix_unix:
	dos2unix $(EXECUTABLE)

# Test the script
test:
	@echo "Testing the program..."
	./$(EXECUTABLE) --help

.PHONY: all clean fix_unix test
