PYTHON ?= python3
export PYTHONDONTWRITEBYTECODE = 1

.PHONY: check test guard

# Run before every commit: the offline tests, then the guard over tracked files and all history.
check: test guard

test:
	$(PYTHON) -m unittest discover -s tests -t . -q

guard:
	$(PYTHON) -m tailscale_ops.guard --history
