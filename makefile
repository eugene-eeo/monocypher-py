all: install_dev test

install_dev:
	-pip uninstall -y monocypher-py
	pip install --editable .[tests,docs]

test:
	py.test --cov monocypher --cov-report term-missing

clean:
	scripts/clean.sh

html:
	cd docs && make html
