SHELL=/bin/bash

PREFIX ?= /usr/local
ALTPREFIX ?= $(HOME)/.local
DESTDIR ?=
BINDIR ?= /bin
MANDIR ?= /share/man

.PHONY: all
all:
	@echo "SecretShare by HacKan (https://hackan.net)"
	@echo "Commands for this makefile:"
	@echo -e \
		"\tpackage-install\n" \
		"\tpackage-uninstall\n" \
		"\tdevenvironment\n" \
		"\tlint\n" \
		"\ttest\n" \
		"\tcoverage\n" \
		"\tclean\n"

.PHONY: clean
clean:
	@rm -vrf \
		build/ \
		dist/ \
		secretshare.egg-info/ \
		secretshare/__pycache__/ \
		secretshare/tests/__pycache__/ \
		cover/ \
		.coverage \
		secretshare/secretshare.egg-info/
	@find . -type f -name "*.pyc" -delete

.PHONY: package-install
package-install:
	python3 setup.py install

.PHONY: package-uninstall
package-uninstall:
	pip uninstall secretshare

.PHONY: lint
lint:
	flake8 --exclude=tests secretshare/
	flake8 --ignore=D100,D101,D102,D103,D104,D105,D106,D107 secretshare/tests/
	pydocstyle -e --match-dir=secretshare .

.PHONY: test
test:
	nosetests --verbose --processes=-1 --detailed-errors

.PHONY: coverage
coverage:
	nosetests --with-coverage --cover-erase --cover-package=secretshare --cover-html

.PHONY: devenvironment
devenvironment:
	@echo "Creating virtualenv"
	@[ -d venv ] || virtualenv -p python3 venv
	@echo "Installing dev dependencies"
	venv/bin/pip install -r requirements-dev.txt
	venv/bin/pip install -r requirements.txt
	@echo "Installing SecretShare"
	@venv/bin/python3 setup.py --fullname
	@venv/bin/python3 setup.py --description
	@venv/bin/python3 setup.py --url
	venv/bin/python3 setup.py install
	@echo -e '\nAll done. You might want to activate the virtualenv (I can not do it for you): `source venv/bin/activate`'

.PHONY: devenvironment-pipenv
devenvironment-pipenv:
	pipenv install -d
	pipenv shell

.PHONY: upload-dev
upload-dev:
	python3 -m twine upload --verbose --sign --repository-url https://test.pypi.org/legacy/ dist/*

.PHONY: upload
upload:
	python3 -m twine upload --verbose --sign dist/*
