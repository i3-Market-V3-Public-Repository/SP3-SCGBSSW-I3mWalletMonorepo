export DIST=$(PWD)/dist/
export TAM=tamarin-prover
export M4=m4 -I .
TEST_REV=Rev4

all: clean dist

dist:
	mkdir -p $(DIST)
	$(MAKE) -C src

clean:
	rm -rf $(DIST)

test: clean dist
	$(TAM) $(DIST)/WalletProtocol_$(TEST_REV).spthy --prove

serve:
	$(MAKE)
	$(TAM) interactive $(DIST)

dev:
	find -name "*.m4*" | entr -r $(MAKE) serve


.PHONY: all clean test serve dev