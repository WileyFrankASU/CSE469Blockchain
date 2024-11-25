# Define the Python script and the executable name
PYTHON_SCRIPT = CSE469Blockchain.py
EXECUTABLE = bchoc

# Default target when `make` is run
all: $(EXECUTABLE)

# Rule to create the executable
$(EXECUTABLE): $(PYTHON_SCRIPT)
	echo '#!/bin/bash' > $(EXECUTABLE)
	echo 'python3 $(PYTHON_SCRIPT) "$$@"' >> $(EXECUTABLE)
	chmod +x $(EXECUTABLE)

# Rule to clean the generated files
clean:
	rm -f $(EXECUTABLE)
