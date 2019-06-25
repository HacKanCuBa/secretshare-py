[![GitHub license](https://img.shields.io/github/license/hackancuba/secretshare-py.svg)](https://github.com/HacKanCuBa/secretshare-py/blob/master/LICENSE) 
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/secretshare-py.svg)](https://pypi.python.org/pypi/secretshare/) 
[![PyPI version](https://badge.fury.io/py/secretshare.svg)](https://badge.fury.io/py/secretshare-py) 
[![GitHub release](https://img.shields.io/github/release/hackancuba/secretshare-py.svg)](https://github.com/hackancuba/secretshare-py/releases/) 
[![GitHub version](https://badge.fury.io/gh/hackancuba%2Fsecretshare-py.svg)](https://badge.fury.io/gh/hackancuba%2Fsecretshare-py) 
[![Updates](https://pyup.io/repos/github/HacKanCuBa/secretshare-py/shield.svg)](https://pyup.io/repos/github/HacKanCuBa/secretshare-py/) 
[![Build Status](https://travis-ci.org/HacKanCuBa/secretshare-py.svg?branch=master)](https://travis-ci.org/HacKanCuBa/secretshare-py) 

# SecretShare

A simple library implementing Adi Shamir's "How to share a secret" algorithm. It is currently very limited since it uses integer arithmetic with primes, thus limiting the size of the shared secret to 8192 bits (1024 bytes). A future version might implement some form of unlimited stream share, but it is not its current goal, which is being used on cryptographic applications.

This library is part of the [Dungeon Password Manager](https://git.rlab.be/hackan/dungeon) project.

## Requirements

* Python 3.6+
* [Passphrase](http://github.com/hackancuba/passphrase-py)

## Installation

Clone the repo an run `make package-install` or, for development purposes, `make devenvironment`. Install dependencies with `pipenv install` or `pip install -r requirements.txt`.

## Usage

```python
from secretshare import Secret, SecretShare, Share


def email(recipient, body):
    """Simulate sending an email."""
    print(f'Recipient: {recipient} - Body: {body}')


# Generate a new random secret
secret = Secret()
# Or use an existing one
secret.value = 12345267890
# Or directly: secret = Secret(1234567890)
# If your secret is not an integer, you can use these methods
# from_bytes()
# from_base64()
# from_hex()

# Share the secret
share_count = 5  # How many pieces will the secret be split into?
threshold = 3    # How many pieces are required to recover the secret?
shamir = SecretShare(threshold, share_count, secret=secret)
shares = shamir.split()
print(shamir.shares)  # [Share(point=1, value=110014556089737955654312725615756332615), Share(point=2, value=270561733948920165984210681299343881767), Share(point=3, value=141359166656608167526319259631339703839), Share(point=4, value=62689221133740423744013068043512010338), Share(point=5, value=34551897380316934637292106535860801264)]
# shamir.shares are the same as `shares`, returned by the split() method

# Now deliver the shares to each recipient
recipients = ('r1@email.com', 'r2@email.com', 'r3@email.com', 'r4@email.com',
              'r5@email.com')
for i, share in enumerate(shares):
    email(recipients[i], str(share))  # Send in base64
# A Share can be converted to several convenient formats:
# bytes(share), share.to_bytes()
# str(share)
# share.to_hex(), hexlify(bytes(share))
# share.to_base64()
# Note: a Secret can be converted the very same way

# To recover the secret, get the share from each holder 
# Each Share has a point and a value
s1 = Share(1, 335597737083070970356431407479895583486)
s2 = Share(2, 138424231339574140617068979728677909704)
s4 = Share()
# They are both encoded together for convenience
s4.from_base64('BQBGQMaGiRzWb0gO3gGEotVL')
# The share count and threshold information is NOT saved anywhere
# so the developer must save it somewhere as it is public
# information and there's no risk in storing it.
# As a matter of fact, those parameters are not really needed to recover a
# secret. If you provide less shares than the threshold then you will get a
# secret value that will be incorrect. There's no way to tell from the result
# whether the amount of shares are actually correct or not.
shamir = SecretShare(threshold, share_count, shares=[s1, s2, s4])
secret = shamir.combine()
print(secret)  # At/V1rI=
print(int(secret))  # 1234567890
# If the wrong number of shares is provided, an incorrect result
# is obtained. This is because this algorithm can't validate the result.
# The developer should verify the secret obtained by comparing into
# a hash, preferably using a secure KDF such as Argon2.
# Alternatively, it might be more convenient to verify each share
# against a hash: if the provided shares are valid the result
# will be correct.
```

## Developing

Install the development requirements, run tests with `make test` and lint with `make lint`. Check for tests coverage with `make coverage` (must be 100%).

## License

**SecretShare** is made by [HacKan](https://hackan.net) under GNU GPL v3.0+. You are free to use, share, modify and share modifications under the terms of that [license](LICENSE).

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
