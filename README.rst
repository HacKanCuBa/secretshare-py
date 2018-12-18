|GitHub license| |PyPI pyversions| |PyPI version| |GitHub release|
|GitHub version| |Updates| |Build Status|

SecretShare
===========

A simple library implementing Adi Shamir’s “How to share a secret”
algorithm. It is currently very limited since it uses integer arithmetic
with primes, thus limiting the size of the shared secret to 512 bits (64
bytes). It is however very useful for cryptographic applications (which
is the intended goal).

Requirements
------------

-  Python 3.6+
-  `Passphrase <http://github.com/hackancuba/passphrase-py>`__

Installation
------------

Clone the repo an run ``make package-install`` or, for development
purposes, ``make devenvironment``. Install dependencies with
``pip install -r requirements.txt``.

Usage
-----

.. code:: python

   from secretshare import SecretShare, Secret, Share

   # Generate a new secret
   secret = Secret()
   # Or use an existing one
   secret.value = b'...'
   # Or directly: secret = Secret(b'...')
   # If your secret is not a byte stream, you can use the methods
   # from_int
   # from_base64
   # from_hex

   # Share the secret
   share_count = 5  # How many pieces will be secret be split into?
   threshold = 3    # How many pieces are required to recover the secret?
   shamir = SecretShare(threshold, share_count, secret)
   shares = shamir.split()

   # Now deliver the shares to each recipient
   for i, share in enumerate(shares):
       email(recipient[i], str(share))  # Send in base64
   # A Share can be converted to several convenient formats:
   # int(share)
   # bytes(share)
   # str(share)
   # hexlify(bytes(share))
   # Note: a Secret can be converted the very same way

   # ...

   # To recover the secret, get the share from each holder 
   s1 = Share()
   s1.from_int(1325546546320210215)
   # A Share has a point and a value
   s2 = Share(2, b'as5d...44a')
   s3 = Share()
   # They are both encoded together for convenience
   s3.from_base64('AAk...ja==')
   # The share count and threshold information is NOT saved anywhere
   # so the developer must save it somewhere as it is public
   # information and there's no risk in storing it.
   shamir = SecretShare(share_count, threshold)
   shamir.shares = [s1, s2, s3]
   secret = shamir.combine()
   # If the wrong number of shares is provided, an incorrect result
   # is obtained.
   # This is because this algorithm can't validate the result.
   # The developer should verify the secret obtained by comparing into
   # a hash, preferably using a secure KDF such as Argon2.
   # Alternatively, it might be more convenient to verify each share
   # against a hash: if the provided shares are correct, the result
   # will be correct.

Developing
----------

Install the development requirements, run tests with ``make test`` and
lint with ``make lint``. Check for tests coverage with ``make coverage``
(currently 100%).

License
-------

**SecretShare** is made by `HacKan <https://hackan.net>`__ under GNU GPL
v3.0+. You are free to use, share, modify and share modifications under
the terms of that `license <LICENSE>`__.

::

   Copyright (C) 2018 HacKan (https://hackan.net)

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.


.. |GitHub license| image:: https://img.shields.io/github/license/hackancuba/secretshare-py.svg
   :target: https://github.com/HacKanCuBa/secretshare-py/blob/master/LICENSE
.. |PyPI pyversions| image:: https://img.shields.io/pypi/pyversions/secretshare.svg
   :target: https://pypi.python.org/pypi/secretshare/
.. |PyPI version| image:: https://badge.fury.io/py/secretshare.svg
   :target: https://badge.fury.io/py/secretshare
.. |GitHub release| image:: https://img.shields.io/github/release/hackancuba/secretshare-py.svg
   :target: https://github.com/hackancuba/secretshare-py/releases/
.. |GitHub version| image:: https://badge.fury.io/gh/hackancuba%2Fsecretshare-py.svg
   :target: https://badge.fury.io/gh/hackancuba%2Fsecretshare-py
.. |Updates| image:: https://pyup.io/repos/github/HacKanCuBa/secretshare-py/shield.svg
   :target: https://pyup.io/repos/github/HacKanCuBa/secretshare-py/
.. |Build Status| image:: https://travis-ci.org/HacKanCuBa/secretshare-py.svg?branch=master
   :target: https://travis-ci.org/HacKanCuBa/secretshare-py
