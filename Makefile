TASK_DIRS := $(patsubst %/metadata.json,%,$(wildcard */metadata.json))

.PHONY: all validate build clean distclean

all: validate

validate:
	python3 scripts/validate.py

build: validate
	@set -e; for task in $(TASK_DIRS); do \
		$(MAKE) -C "$$task" all; \
	done

clean:
	@set -e; for task in $(TASK_DIRS); do \
		$(MAKE) -C "$$task" clean; \
	done

distclean: clean
	$(MAKE) -C CVE-2024-1086 distclean
