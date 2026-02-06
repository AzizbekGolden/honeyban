.PHONY: core core-install core-clean website

core:
	$(MAKE) -C core all

core-install:
	$(MAKE) -C core install

core-clean:
	$(MAKE) -C core clean

website:
	python3 -m http.server 8000 --directory website

