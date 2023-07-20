FILENAME=$(shell $(M4) ./filename.m4i)
SPTHY=$(DIST)$(FILENAME)

all: $(SPTHY)

$(SPTHY):
	@echo ------------------------------------------------------------------------------
	@echo Building $(FILENAME)
	@echo ------------------------------------------------------------------------------
	$(M4) ./index.m4i > $(SPTHY)

.PHONY: all
