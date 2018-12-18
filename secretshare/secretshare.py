#  ***************************************************************************
#  This file is part of ShareSecret:
#  A cryptographically secure secret sharing implementing Shamir's secret share
#  Copyright (C) <2018>  <Ivan Ariel Barrera Oro>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  ***************************************************************************

"""Share secrets in a cryptographically secure way.

Implements Shamir's secret sharing algorithm.
"""

from binascii import unhexlify, b2a_base64, a2b_base64, Error as binascii_Error
from typing import List
from math import ceil

from passphrase.random import randint
from passphrase.secrets import randbelow

from .calc import int_to_bytes, compute_closest_bigger_equal_pow2, bytes_to_int
from .calc import lagrange_interpolate, eval_poly_at_point


class Primes:
    """Helper module to handle prime numbers."""

    # The following primes are the closest bigger than 2^bits-1, assuring the
    # required number of bits of security is met.
    _PRIMES = {
        8: 257,
        16: 65537,
        32: 4294967311,
        64: 18446744073709551629,
        128: 340282366920938463463374607431768211507,
        # flake8: noqa: E501
        256: 115792089237316195423570985008687907853269984665640564039457584007913129640233,
        512: 2 ** 521 - 1,  # 13th Mersenne Prime
    }

    @staticmethod
    def max_bits():
        """Maximum amount of bits than can be processed with these primes."""
        return list(Primes._PRIMES.keys())[-1]

    @staticmethod
    def max_bytes():
        """Maximum amount of bytes than can be processed with these primes."""
        return Primes.max_bits() // 8

    @classmethod
    def get(cls, bits: int) -> int:
        """Get a prime number for the given number of security bits."""
        return cls._PRIMES.get(bits)


class AbstractValue:
    """Abstract helper class to handle secret and share values."""

    @property
    def value(self) -> bytes:
        return self._value

    @value.setter
    def value(self, value: bytes):
        if not isinstance(value, bytes):
            raise TypeError('value must be bytes')
        self._value = value

    def __init__(self, value: bytes = b''):
        self.value = value

    def __bytes__(self) -> bytes:
        return self.value

    def __bool__(self) -> bool:
        return bool(self.value)

    def __hex__(self) -> str:
        return hex(int(self))

    def __oct__(self) -> str:
        return oct(int(self))

    def __str__(self) -> str:
        # b2a_base64 adds a newline char at the end
        return b2a_base64(bytes(self)).decode('utf8')[:-1]

    def __int__(self) -> int:
        return bytes_to_int(bytes(self))

    def __len__(self) -> int:
        return len(bytes(self))

    def __index__(self) -> int:
        return int(self)

    def from_bytes(self, bytes_value: bytes):
        """Set object values from bytes."""
        if not isinstance(bytes_value, bytes):
            raise TypeError('bytes_value must be bytes')
        self.value = bytes_value

    def from_int(self, num_value: int):
        """Set object values from integer."""
        self.from_bytes(int_to_bytes(num_value))

    def from_hex(self, hex_value: any):
        """Set object values from hex string."""
        try:
            bts = unhexlify(hex_value)
        except binascii_Error:
            if hex_value[:2] == '0x':
                hex_value = hex_value[2:]
            bts = unhexlify('0' + hex_value)
        self.from_bytes(bts)

    def from_base64(self, b64_value: any):
        """Set object values from base64 encoded string."""
        bts = a2b_base64(b64_value)
        self.from_bytes(bts)

    def to_base64(self) -> bytes:
        """Get base64 representation conforming to RFC 3548."""
        return b2a_base64(bytes(self))


class Secret(AbstractValue):
    """Helper class to handle a secret value."""

    @property
    def value(self) -> bytes:
        return self._value

    @value.setter
    def value(self, value: bytes):
        """Secret value to split, in bytes.

        Warning: if the value begins with null bytes, they will be lost in
        translation to integers and the secret won't be recoverable!
        """
        if not isinstance(value, bytes):
            raise TypeError('value must be bytes')
        if not value:
            raise ValueError('value can not be empty')
        if value[0] == 0:
            raise ValueError('value can not begin with a null byte')
        max_bytes = Primes.max_bytes()
        if len(value) > max_bytes:
            raise ValueError(
                'value has to be smaller or equal than {} bytes'.format(max_bytes)
            )
        self._value = value

    @staticmethod
    def random():
        """Generate a random value for the secret."""
        # Generating a random integer and then converting it to bytes ensures
        # that information won't be lost in translation, which happened in a
        # previous version using randbytes() when the value began with null
        # bytes '\x00' (the are removed in translation)
        return int_to_bytes(randint(Primes.max_bits()))

    def __init__(self, value: bytes = b''):
        if not value:
            value = Secret.random()
        super().__init__(value)


class Share(AbstractValue):
    """Helper class to handle a share value."""

    @property
    def point(self) -> int:
        return self._point

    @point.setter
    def point(self, point: int):
        if not isinstance(point, int):
            raise TypeError('point must be integer')
        if point < 1:
            raise ValueError('point must be bigger than or equal to 1')
        max_point = Share._get_max_point()
        if point > max_point:
            raise ValueError(
                'point must be smaller than or equal to {}'.format(max_point)
            )
        self._point = point

    @staticmethod
    def _get_max_point() -> int:
        return Primes.max_bits() - 1

    @staticmethod
    def _get_max_point_bytes_len() -> int:
        return ceil(Share._get_max_point().bit_length() / 8)

    def __init__(self, point: int = 1, value: bytes = b''):
        super().__init__(value)
        self.point = point

    def __bytes__(self) -> bytes:
        point_bytes = self.point.to_bytes(Share._get_max_point_bytes_len(),
                                          'big')
        # reverse point_bytes because most of the times it has a \x00 as MSB,
        # which gets lost on encodings/transformations such as int
        return point_bytes[::-1] + self.value

    def __index__(self) -> int:
        return self.point

    def from_bytes(self, bytes_value: bytes):
        """Set object values from bytes."""
        if not isinstance(bytes_value, bytes):
            raise TypeError('bytes_value must be bytes')

        self.point = bytes_to_int(
            bytes_value[:Share._get_max_point_bytes_len()][::-1]
        )
        self.value = bytes_value[Share._get_max_point_bytes_len():]


class SecretShare:
    """Shamir's Secret Share using integer arithmetic.

    Largely based on
    https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing#Python_example
    """

    def __init__(self, threshold: int = 2, share_count: int = 3,
                 secret: Secret = None):
        self.threshold = threshold
        self.share_count = share_count
        self.secret = secret if secret else Secret()
        self.shares = []

    def _get_random_int(self):
        return randbelow(self.prime)

    @property
    def threshold(self) -> int:
        """Set the number of pieces required to recover the secret."""
        return self._threshold

    @threshold.setter
    def threshold(self, threshold: int):
        """Set the number of pieces required to recover the secret."""
        if not isinstance(threshold, int):
            raise TypeError('threshold must be int')
        if threshold < 2:
            raise ValueError('threshold must be >= 2')
        self._threshold = threshold

    @property
    def share_count(self) -> int:
        """Get the share count (number of pieces the secret is split)."""
        return self._share_count

    @share_count.setter
    def share_count(self, share_count: int):
        """Set the share count (number of pieces the secret is split)."""
        if not isinstance(share_count, int):
            raise TypeError('share_count must be int')
        if share_count < 2:
            raise ValueError('share_count must be >= 2')
        self._share_count = share_count

    @property
    def secret(self) -> Secret:
        """Get the secret."""
        return self._secret

    @secret.setter
    def secret(self, secret: Secret):
        """Set a secret to split and share."""
        if not isinstance(secret, Secret):
            raise TypeError('secret must be Secret')
        # The Secret class ensures it's not empty
        self._secret = secret

    @property
    def shares(self) -> List[Share]:
        """Get the shares of a split secret."""
        return self._shares

    @shares.setter
    def shares(self, shares: List[Share]):
        """Set the shares of a split secret."""
        if not isinstance(shares, list):
            raise TypeError('shares must be list')
        for share in shares:
            if not isinstance(share, Share):
                raise TypeError('shares must be a list of Share')
        self._shares = shares

    @property
    def prime(self) -> int:
        """Get the current prime number in use for the field."""
        # if not self.secret:
        #     raise ValueError('secret not set, can not define prime number')
        return Primes.get(compute_closest_bigger_equal_pow2(len(self.secret)) * 8)

    @property
    def poly(self) -> List[int]:
        """Get the polynomial to use for Shamir's secret splitting."""
        # if not self.secret or not self.threshold:
        #     raise ValueError('secret not set or threshold not set, can not '
        #                      'define a polynomial')
        return [int(self.secret)] + \
               [self._get_random_int() for _ in range(self.threshold - 1)]

    @property
    def max_share_count(self) -> int:
        """Get the maximum share count."""
        # if not self.secret:
        #     raise ValueError('secret not set, can not compute max share count')
        # max share count is one less than the max number of bytes that can be
        # computed using the selected prime, which in turn depends on the
        # secret length
        return compute_closest_bigger_equal_pow2(len(self.secret)) * 8 - 1

    def split(self) -> list:
        """Split a secret securely using Shamir's algorithm."""
        # Validations
        max_share_count = self.max_share_count
        if self.share_count > max_share_count:
            raise ValueError('share_count must be lower than {} for the given '
                             'secret'.format(max_share_count))
        if self.threshold > self.share_count:
            raise ValueError('share_count must be bigger than or equal to '
                             'threshold')

        poly = self.poly
        prime = self.prime
        shares = []
        for i in range(1, self.share_count + 1):
            value = eval_poly_at_point(poly, i, prime)
            shares.append(Share(i, int_to_bytes(value)))
        self.shares = shares
        return shares

    def combine(self) -> Secret:
        """Combine shares of a split secret to recover it."""
        if len(self.shares) < 2:
            raise ValueError('shares must have 2 or more Share')
        if len(self.shares) > self.share_count:
            raise ValueError('shares can not be more than the share count')

        x_s = [share.point for share in self.shares]
        y_s = [bytes_to_int(share.value) for share in self.shares]
        secret_int = lagrange_interpolate(0, x_s, y_s, self.prime)
        secret = Secret()
        secret.from_int(secret_int)
        self.secret = secret
        return secret
