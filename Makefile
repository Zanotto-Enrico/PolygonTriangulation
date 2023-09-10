PROGRAM_NAME = ./out/program

# Compiler tags
CXX = g++
CXXFLAGS = -std=c++11 -w -g 

# source files
SOURCES = algebra.cpp program.cpp tessellation.cpp

# headers list
HEADERS = headers.hpp

# Create the "out" directory if it doesn't exist
$(shell mkdir -p ./out)

# compilation
$(PROGRAM_NAME): $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(PROGRAM_NAME)

# target all set as default
all: $(PROGRAM_NAME)

.PHONY: clean