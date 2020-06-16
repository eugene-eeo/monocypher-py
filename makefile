all: install_dev test

install_dev:
	-pip uninstall -y monocypher-py
	pip install --editable .

test:
	py.test --cov monocypher --cov-report term-missing
