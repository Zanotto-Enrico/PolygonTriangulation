# Nome del programma da generare
PROGRAM_NAME = program

# Compilatore da utilizzare
CXX = g++
CXXFLAGS = -std=c++11 -w -g 

# Lista dei file sorgenti
SOURCES = algebra.cpp program.cpp tessellation.cpp

# Lista dei file header
HEADERS = headers.hpp

# Generazione dell'eseguibile
$(PROGRAM_NAME): $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(PROGRAM_NAME)



# Imposta il target 'all' come predefinito
all: $(PROGRAM_NAME)

.PHONY: clean
