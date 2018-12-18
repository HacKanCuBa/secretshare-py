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

from unittest import TestCase

from passphrase.secrets import randbelow
from passphrase.random import randbytes

from secretshare.tests.constants import WRONGTYPES_INT, WRONGTYPES_LIST_TUPLE,\
    WRONGTYPES_ITER
from secretshare.calc import lagrange_interpolate, int_to_bytes, \
    eval_poly_at_point, compute_closest_bigger_equal_pow2, _product,\
    _extended_gcd, _divmod, bytes_to_int


class TestValidInputs(TestCase):

    def test_product(self):
        nums = [randbelow(100) for _ in range(10)]
        result = 1
        for num in nums:
            result *= num
        self.assertEqual(result, _product(nums))

    def test_extended_gcd(self):
        result = _extended_gcd(240, 46)
        self.assertEqual(result, (-9, 47))
        result = _extended_gcd(-257, 7)
        self.assertEqual(result, (-3, -110))

    def test_divmod(self):
        result = _divmod(1, 100, 7)
        self.assertEqual(result, -3)
        result = _divmod(3, 256, 5)
        self.assertEqual(result, 3)

    def test_int_to_bytes(self):
        result = int_to_bytes(1)
        self.assertEqual(result, b'\x01')
        result = int_to_bytes(-1)
        self.assertEqual(result, b'\xff')
        result = int_to_bytes(0)
        self.assertEqual(result, b'\x00')

    def test_bytes_to_int(self):
        result = bytes_to_int(b'\x01')
        self.assertEqual(result, 1)
        result = bytes_to_int(b'\xff', True)
        self.assertEqual(result, -1)
        result = bytes_to_int(b'\x00')
        self.assertEqual(result, 0)

    def test_compute_closest_bigger_equal_pow2(self):
        result = compute_closest_bigger_equal_pow2(0)
        self.assertEqual(result, 2)
        result = compute_closest_bigger_equal_pow2(1)
        self.assertEqual(result, 2)
        result = compute_closest_bigger_equal_pow2(2)
        self.assertEqual(result, 2)
        result = compute_closest_bigger_equal_pow2(10)
        self.assertEqual(result, 16)

    def test_eval_poly_at_point(self):
        poly = [2, 3, 4, 5]
        prime = 7
        result = eval_poly_at_point(poly, 1, prime)
        self.assertEqual(result, 0)
        result = eval_poly_at_point(poly, 0, prime)
        self.assertEqual(result, 2)
        result = eval_poly_at_point(poly, -1, prime)
        self.assertEqual(result, 5)

    def test_lagrange_interpolate(self):
        result = lagrange_interpolate(1, [0, 2, 4], [1, 5, 17], 11)
        self.assertEqual(result, 2)
        result = lagrange_interpolate(0, [2, 4, 6], [3, 4, 6], 7)
        self.assertEqual(result, 3)


class TestInvalidInputs(TestCase):

    def test_product(self):
        for wrongtype in WRONGTYPES_ITER:
            self.assertRaises(TypeError, _product, wrongtype)

    def test_extended_gcd(self):
        for wrongtype in WRONGTYPES_INT:
            self.assertRaises(TypeError, _extended_gcd, wrongtype, 1)
            self.assertRaises(TypeError, _extended_gcd, 1, wrongtype)

    def test_divmod(self):
        for wrongtype in WRONGTYPES_INT:
            self.assertRaises(TypeError, _divmod, wrongtype, 1, 2)
            self.assertRaises(TypeError, _divmod, 1, wrongtype, 2)
            self.assertRaises(TypeError, _divmod, 1, 1, wrongtype)
        self.assertRaises(ValueError, _divmod, 1, 1, -1)

    def test_int_to_bytes(self):
        for wrongtype in WRONGTYPES_INT:
            self.assertRaises(TypeError, int_to_bytes, wrongtype)

    def test_compute_closest_bigger_equal_pow2(self):
        for wrongtype in WRONGTYPES_INT:
            self.assertRaises(TypeError, compute_closest_bigger_equal_pow2,
                              wrongtype)
        self.assertRaises(ValueError, compute_closest_bigger_equal_pow2, -1)

    def test_eval_poly_at_point(self):
        for wrongtype in WRONGTYPES_INT:
            self.assertRaises(TypeError, eval_poly_at_point, [], wrongtype, 2)
            self.assertRaises(TypeError, eval_poly_at_point, [], 1, wrongtype)
        for wrongtype in WRONGTYPES_LIST_TUPLE:
            self.assertRaises(TypeError, eval_poly_at_point, wrongtype, 1, 2)
        self.assertRaises(ValueError, eval_poly_at_point, [], 1, -1)

    def test_lagrange_interpolate(self):
        for wrongtype in WRONGTYPES_INT:
            self.assertRaises(TypeError, lagrange_interpolate, wrongtype, [],
                              [], 2)
            self.assertRaises(TypeError, lagrange_interpolate, 1, [],
                              [], wrongtype)
        for wrongtype in WRONGTYPES_LIST_TUPLE:
            self.assertRaises(TypeError, lagrange_interpolate, 1, wrongtype,
                              [], 2)
            self.assertRaises(TypeError, lagrange_interpolate, 1, [],
                              wrongtype, 2)
        self.assertRaises(ValueError, lagrange_interpolate, 1, [],
                          [], -1)
        self.assertRaises(AssertionError, lagrange_interpolate, 1, [1, 1],
                          [1, 2], 3)
