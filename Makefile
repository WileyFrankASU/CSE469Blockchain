
PYTHON_SCRIPT = CSE469Blockchain.py
EXECUTABLE = bchoc


all: $(EXECUTABLE)


$(EXECUTABLE): $(PYTHON_SCRIPT)
	echo '#!/bin/bash' > $(EXECUTABLE)
	echo 'python3 $(PYTHON_SCRIPT) "$$@"' >> $(EXECUTABLE)
	chmod +x $(EXECUTABLE)


clean:
	rm -f $(EXECUTABLE)
