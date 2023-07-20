SUBDIRS := $(wildcard */.)

all: $(SUBDIRS)
$(SUBDIRS):
	@echo Building $@...
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS)
