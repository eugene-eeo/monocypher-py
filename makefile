dev: install_dev test

install_dev:
	-pip uninstall -y monocypher-py
	pip install --verbose --editable .[tests,docs]

test:
	py.test

test_ci:
	HYPOTHESIS_PROFILE=ci py.test

clean:
	scripts/clean.sh

html:
	rm -rf docs/_build/html
	cd docs && make html

full: clean install_dev test_ci html
