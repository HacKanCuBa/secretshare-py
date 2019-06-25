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

from abc import ABC, abstractmethod
from binascii import a2b_base64, b2a_base64
from math import ceil
from typing import Iterator, List, Optional, Sequence, Tuple, Union

from .calc import bytes_to_int, int_to_bytes
from .calc import eval_poly_at_point, lagrange_interpolate
from .primes import Primes


class AbstractRepr(ABC):
    """Abstract class that provides a generic repr method."""

    @property
    def _attributes(self) -> Tuple[str, ...]:
        """Get a tuple of all object's attributes alphabetically ordered.

        It considers both slots and otherwise.
        Do not override this method.
        """
        # __slots__ and __dict__ might coexist, where a parent might define
        # __slots__, and a child not (thus using __dict__)
        attrs = set()
        if hasattr(self, '__slots__'):
            for cls in self.__class__.__mro__:
                attrs.update(getattr(cls, '__slots__', tuple()))
        if hasattr(self, '__dict__'):
            attrs.update(self.__dict__.keys())
        return tuple(sorted(attrs))

    def _get_attributes(self) -> Iterator[str]:
        """Get the object's attributes, using getters if any.

        This means that private attributes that have public counterparts are
        exported solely as the public counterpart, whereas private without
        public counterparts are exported as is.
        """
        return (
            attr[1:]
            if attr[0] == '_' and hasattr(self.__class__, attr[1:])
            else attr
            for attr in self._attributes
        )

    def __repr__(self) -> str:
        """Get the unique representation of the object as string."""
        attributes_listed = ', '.join(f'{attr}={getattr(self, attr, None)}'
                                      for attr in self._get_attributes())
        return f'{self.__class__.__name__}({attributes_listed})'


class AbstractValue(AbstractRepr):
    """Abstract helper class to handle secret and share values."""

    __slots__ = '_value',

    @abstractmethod
    def __bytes__(self) -> bytes:
        """Get the bytes representation of the object."""

    def __str__(self) -> str:
        """Get the string representation of the object."""
        # b2a_base64 adds a newline char at the end
        return self.to_base64().decode('utf8')[:-1]

    def __int__(self) -> int:
        """Get the value of the object as integer."""
        return self.value

    def __init__(self, value: Optional[int] = None):
        """Handle values."""
        self.value = value if value else 1

    @staticmethod
    def max_value() -> int:
        """Get the biggest possible value."""
        return Primes.biggest() - 1

    @property
    def value(self) -> int:
        """Get the value."""
        return self._value

    @value.setter
    def value(self, value: int) -> None:
        """Set the value."""
        if not isinstance(value, int):
            raise TypeError('value must be integer')
        if value <= 0:
            raise ValueError('value must be bigger than 0')
        max_value = self.max_value()
        if value > max_value:
            raise ValueError(
                f'value has to be smaller or equal than {max_value}'
            )
        self._value = value

    @abstractmethod
    def from_bytes(self, bytes_value: bytes) -> None:
        """Set object values from bytes."""

    def from_hex(self, hex_value: str) -> None:
        """Set object values from hex string (support beggining with 0x)."""
        try:
            bts = bytes.fromhex(hex_value)
        except ValueError:
            hex_val = hex_value[2:] if hex_value[:2] == '0x' else hex_value
            hex_ = '0' + hex_val if len(hex_val) % 2 else hex_val
            bts = bytes.fromhex(hex_)
        self.from_bytes(bts)

    def from_base64(self, b64_value: Union[bytes, str]) -> None:
        """Set object values from a base64 encoded string."""
        bts = a2b_base64(b64_value)
        self.from_bytes(bts)

    def to_hex(self) -> str:
        """Get the hexadecimal string representation of the object."""
        return bytes(self).hex()

    def to_base64(self) -> bytes:
        """Get the base64 representation of the object conforming to RFC 3548."""
        return b2a_base64(bytes(self))

    def to_bytes(self) -> bytes:
        """Get the representation of the object as bytes (same as bytes(`self`))."""
        return bytes(self)


class Secret(AbstractValue):
    """Helper class to handle a secret value."""

    def __init__(self, value: Optional[int] = None):
        """Handle a secret, providing several helper functions.

        :param value: A secret value to store. If not indicated, a random one
                      is generated.
        """
        super().__init__(value)
        if not value:
            self.random()

    def __bytes__(self) -> bytes:
        """Get the value of the secret as bytes."""
        return int_to_bytes(self.value)

    @staticmethod
    def max_bits() -> int:
        """Get the maximum number of bits the secret can hold."""
        return Primes.max_bits()

    @classmethod
    def max_bytes(cls) -> int:
        """Get the maximum number of bytes the secret can hold."""
        return cls.max_bits() // 8

    def from_bytes(self, bytes_value: bytes) -> None:
        """Set secret value from bytes."""
        if not isinstance(bytes_value, bytes):
            raise TypeError('bytes_value must be bytes')
        if bytes_value[0] == 0:
            raise ValueError('bytes_value can not begin with a null byte')
        self.value = bytes_to_int(bytes_value)

    def random(self, bits: Optional[int] = None) -> None:
        """Generate a random value for the secret.

        :param bits: Number of bits to use for generation (defaults to the
                     maximum number of bits possible).
        """
        num_bits = bits if bits else self.max_bits()
        self.value = Primes.random_int(num_bits)

    def bit_length(self) -> int:
        """Gte the number of bits necessary to represent self in binary."""
        return self.value.bit_length()


class Share(AbstractValue):
    """Helper class to handle a share value.

    The share has a point and a value for that point, evaluated on a polynomial
    function.
    """

    __slots__ = '_point',

    @property
    def _max_point_bytes_len(self) -> int:
        return ceil(self.max_point().bit_length() / 8)

    def __init__(self, point: int = 1, value: Optional[int] = None):
        """Create a share consisting on a point and a value.

        The point is evaluated on a polynomial function, obtaining the value.

        :param point: Point of the polynomial function.
        :param value: Value of the function evaluated at the given point.
        """
        super().__init__(value)
        self.point = point

    def __index__(self) -> int:
        """Get the value of `point` for use of the object as index."""
        return self.point

    def __bytes__(self) -> bytes:
        """Get the representation in bytes of the share."""
        point_bytes = self.point.to_bytes(self._max_point_bytes_len, 'big')
        # reverse point_bytes because most of the times it has a \x00 as MSB,
        # which gets lost on encodings/transformations such as int
        return point_bytes[::-1] + int_to_bytes(self.value)

    def from_bytes(self, bytes_value: bytes) -> None:
        """Set share point and value from bytes.

        :param bytes_value: The share in bytes, as obtained by bytes(share).
        """
        if not isinstance(bytes_value, bytes):
            raise TypeError('bytes_value must be bytes')

        point_bytes_len = self._max_point_bytes_len
        self.point = bytes_to_int(bytes_value[:point_bytes_len][::-1])
        self.value = bytes_to_int(bytes_value[point_bytes_len:])

    @staticmethod
    def max_point() -> int:
        """Get the biggest possible point."""
        return Primes.max_bits() - 1

    @property
    def point(self) -> int:
        """Get the share point."""
        return self._point

    @point.setter
    def point(self, point: int) -> None:
        """Set the share point."""
        if not isinstance(point, int):
            raise TypeError('point must be integer')
        if point < 1:
            raise ValueError('point must be bigger than or equal to 1')
        max_point = self.max_point()
        if point > max_point:
            raise ValueError(
                f'point must be smaller than or equal to {max_point}'
            )
        self._point = point


class SecretShare(AbstractRepr):
    """Shamir's Secret Share using integer arithmetic.

    Largely based on
    https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Python_example
    """

    __slots__ = '_secret', '_share_count', '_shares', '_threshold',

    def __init__(self, threshold: int = 2, share_count: int = 3, *,
                 secret: Optional[Secret] = None,
                 shares: Optional[Sequence[Share]] = None):
        """Share a secret using Shamir's secret share algorithm.

        :param threshold: Minimal amount of parts required to recover the
                          secret, bigger or equal to 2 (defaults to 2).
        :param share_count: Count of shares (secret pieces), bigger or equal to
                            2 (defaults to 3).
        :param secret: A `Secret` object containing the secret to be shared. If
                       not set, a random one is generated.
        """
        self.threshold = threshold
        self.share_count = share_count
        self.secret = secret if secret else Secret()
        self.shares = shares if shares else []

    def _prime(self, *, combine: bool = False) -> int:
        """Get the prime number in use for the field.

        :param combine: True to get the number for a combination of shares,
                        False to get the number for a secret splitting.
        """
        if combine:
            num = max(share.value for share in self.shares)
        else:
            num = int(self.secret)
        return Primes.get_closest(num=num)

    @property
    def _prime_for_split(self) -> int:
        """Get the prime used to split a secret."""
        return self._prime()

    @property
    def _prime_for_combine(self) -> int:
        """Get the prime used to combine shares."""
        return self._prime(combine=True)

    def _generate_random_poly(self) -> List[int]:
        """Generate a random polynomial for Shamir's secret splitting."""
        bits = Primes.get_closest_bits(num=int(self.secret))
        return [int(self.secret)] + \
               [Primes.random_int(bits) for _ in range(self.threshold - 1)]

    @property
    def threshold(self) -> int:
        """Get the number of pieces required to recover the secret."""
        return self._threshold

    @threshold.setter
    def threshold(self, threshold: int) -> None:
        """Set the number of pieces required to recover the secret."""
        if not isinstance(threshold, int):
            raise TypeError('threshold must be int')
        if threshold < 2:
            raise ValueError('threshold must be >= 2')
        self._threshold: int = threshold

    @property
    def share_count(self) -> int:
        """Get the share count (number of pieces the secret is split)."""
        return self._share_count

    @share_count.setter
    def share_count(self, share_count: int) -> None:
        """Set the share count (number of pieces the secret is split)."""
        if not isinstance(share_count, int):
            raise TypeError('share_count must be int')
        if share_count < 2:
            raise ValueError('share_count must be >= 2')
        self._share_count: int = share_count

    @property
    def secret(self) -> Secret:
        """Get the secret."""
        return self._secret

    @secret.setter
    def secret(self, secret: Secret) -> None:
        """Set a secret to split and share.

        Note: this will reset the shares (if any) and the polynomial.
        """
        if not isinstance(secret, Secret):
            raise TypeError('secret must be Secret')
        # The Secret class ensures it's not empty
        self._secret: Secret = secret
        self._shares = []

    @property
    def shares(self) -> List[Share]:
        """Get the shares of a split secret."""
        return self._shares

    @shares.setter
    def shares(self, shares: Sequence[Share]) -> None:
        """Set the shares of a split secret."""
        if not isinstance(shares, Sequence):
            raise TypeError('shares must be sequence of Share objects')
        for share in shares:
            if not isinstance(share, Share):
                raise TypeError('shares must be sequence of Share objects')
        self._shares: List[Share] = list(shares)

    @property
    def max_share_count(self) -> int:
        """Get the maximum share count for splitting a given secret.

        Note: the secret must be set from beforehand.
        """
        # max share count is one less than the max number of bits that can be
        # computed using the selected prime, which in turn depends on the
        # secret length
        return self.secret.value.bit_length() - 1

    def split(self) -> List[Share]:
        """Split a secret securely using Shamir's algorithm.

        Every call to this method will compute different shares.
        """
        # Validations
        max_share_count = self.max_share_count
        prime = self._prime_for_split
        if self.share_count > max_share_count:
            raise ValueError(f'share_count must be lower than {max_share_count} '
                             f'for the given secret')
        if self.threshold > self.share_count:
            raise ValueError('share_count must be bigger than or equal to '
                             'threshold')

        self.shares = []
        poly = self._generate_random_poly()
        for point in range(1, self.share_count + 1):
            share = Share(point, value=eval_poly_at_point(poly, point, prime))
            self.shares.append(share)
        return self.shares

    def combine(self) -> Secret:
        """Combine shares of a split secret to recover it."""
        if len(self.shares) > self.share_count:
            raise ValueError(
                'the number of shares can not be more than the share count'
            )
        if len(self.shares) < self.threshold:
            raise ValueError(
                'the number of shares must be bigger or equal than the threshold'
            )

        prime = self._prime_for_combine
        x_s = [share.point for share in self.shares]
        y_s = [share.value for share in self.shares]
        self.secret = Secret(lagrange_interpolate(0, x_s, y_s, prime))
        return self.secret
