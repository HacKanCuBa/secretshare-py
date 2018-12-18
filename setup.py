#!/usr/bin/env python3

"""SecretShare installer script.

Install with `setup.py install`.

"""

from setuptools import setup
from secretshare import __version__ as version


def _readme():
    with open('README.rst') as rst:
        return rst.read()


setup(
    name='secretshare',
    version=version,
    description='Share a secret securelly implementing Shamir\'s secret share',
    long_description=_readme(),
    classifiers=[
      'Development Status :: 3 - Alpha',
      'Environment :: Other Environment',
      'Intended Audience :: Developers',
      'License :: OSI Approved :: GNU General Public License v3 or later '
      '(GPLv3+)',
      'Natural Language :: English',
      'Operating System :: POSIX :: Linux',
      'Programming Language :: Python :: 3',
      'Programming Language :: Python :: 3.6',
      'Topic :: Security :: Cryptography',
      'Topic :: Utilities'
    ],
    platforms=[
      'POSIX :: Linux'
    ],
    keywords='cryptography shamir secret share security',
    url='http://github.com/hackancuba/secretshare-py',
    download_url='https://github.com/HacKanCuBa/secretshare-py/archive/'
                 'v{}.tar.gz'.format(version),
    author='HacKan',
    author_email='hackan@gmail.com',
    license='GPLv3+',
    packages=['secretshare'],
    python_requires='>=3.6',
    install_requires=[
        'hc-passphrase',
    ],
    test_suite='nose.collector',
    tests_require=['nose'],
    zip_safe=False,
)
