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

"""Auxiliary calculations for ShareSecrets."""

from functools import reduce
from math import ceil, log2
from operator import mul
from typing import List, Iterable, Tuple

# This file is largely based on
# https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing#Python_example


def compute_closest_bigger_equal_pow2(value: int) -> int:
    """Calculate the closest power of 2 bigger than or equal to given value."""
    if not isinstance(value, int):
        raise TypeError('value must be integer')
    if value < 0:
        raise ValueError('value must be positive')

    if value < 3:
        return 2
    return 2 ** ceil(log2(value))


def eval_poly_at_point(poly: List[int], point: int, prime: int) -> int:
    """Evaluate polynomial (coefficient tuple) at given point."""
    if not isinstance(point, int) or not isinstance(prime, int):
        raise TypeError('point and prime must be integers')
    if not isinstance(poly, list):
        raise TypeError('poly must be a list of integers')
    if prime < 2:
        raise ValueError('prime must be positive and prime')

    accum = 0
    for coeff in reversed(poly):
        accum *= point
        accum += coeff
        accum %= prime
    return accum


def int_to_bytes(num: int) -> bytes:
    """Convert an integer number into bytes."""
    if not isinstance(num, int):
        raise TypeError('num_value must be integer')
    signed = num < 0
    length = ceil(num.bit_length() / 8) or 1  # For 0, bit_length is 0
    return num.to_bytes(length, 'big', signed=signed)


def bytes_to_int(bts: bytes, signed: bool = False) -> int:
    """Convert a string of bytes to an integer number.

    Whether the final int should be signed or not can't be determined, so it
    must be specified.

    Note: reversibility is not assured! I.E.: if the bytes string begins with
    null values, those will be lost and converting the resulting integer into
    bytes will yield a different value.
    """
    if not isinstance(bts, bytes):
        raise TypeError('bts must be bytes')
    return int.from_bytes(bts, 'big', signed=signed)


def _extended_gcd(a: int, b: int) -> Tuple[int, int]:
    """Calculate the extended Euclidean algorithm between a and b.

    Division in integers modulus p means finding the inverse of the
    denominator modulo p and then multiplying the numerator by this
    inverse (Note: inverse of A is B such that A*B % p == 1) this can
    be computed via extended Euclidean algorithm
    http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
    """
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError('a and b must be integers')
    # if a < 0 or b < 0:
    #     raise ValueError('a and b must be bigger than 0')

    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y


def _divmod(num: int, den: int, prime: int) -> int:
    """Compute integer division modulo prime.

    The return value will be such that the following is true:
    den * _divmod(num, den, p) % p == num
    """
    if not isinstance(num, int) \
            or not isinstance(den, int) \
            or not isinstance(prime, int):
        raise TypeError('num, den and prime must be integers')
    if prime < 2:
        raise ValueError('prime must be positive and prime')

    inv, _ = _extended_gcd(den, prime)
    return num * inv


def _product(values: Iterable) -> int:
    """Compute the product over the given values."""
    if not isinstance(values, Iterable):
        raise TypeError('values must be an iterable of numbers')
    return reduce(mul, values, 1)


def lagrange_interpolate(x: int, x_s: List[int], y_s: List[int], prime: int) -> int:
    """Find the y-value for the given x, given any number of (x, y) points.

    k points will define a polynomial of up to kth order
    """
    if not isinstance(x, int) or not isinstance(prime, int):
        raise TypeError('x and p must be integers')
    if not isinstance(x_s, list) or not isinstance(y_s, list):
        raise TypeError('x_s and y_s must be lists of integers')
    if prime < 2:
        raise ValueError('prime must be positive and prime')

    k = len(x_s)
    assert k == len(set(x_s)), 'x_s points must be distinct'
    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(_product(x - o for o in others))
        dens.append(_product(cur - o for o in others))
    den = _product(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % prime, dens[i], prime)
               for i in range(k)])
    return (_divmod(num, den, prime) + prime) % prime
