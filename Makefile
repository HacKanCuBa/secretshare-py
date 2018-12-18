SHELL=/bin/bash

PREFIX ?= /usr/local
ALTPREFIX ?= $(HOME)/.local
DESTDIR ?=
BINDIR ?= /bin
MANDIR ?= /share/man

all:
	@echo "SecretShare by HacKan (https://hackan.net)"
	@echo "Commands for this makefile:"
	@echo -e "\tpackage-install\n\tpackage-uninstall\n\tdevenvironment\n\tlint\n\ttest\n\tcoverage\n\tclean"

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

package-install:
	python3 setup.py install

package-uninstall:
	pip uninstall secretshare

lint:
	flake8 --exclude=venv/ .
	pydocstyle -e --match-dir=secretshare .

test:
	nosetests -v

coverage:
	nosetests --with-coverage --cover-erase --cover-package=secretshare --cover-html

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

.PHONY: lint test coverage clean devenvironment package-install package-uninstall

