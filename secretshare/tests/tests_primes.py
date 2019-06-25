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

from secretshare.primes import Primes


class TestValidInputs(TestCase):

    def test_primes_max_bits(self):
        self.assertEqual(Primes.max_bits(), 8192)

    def test_primes_min_bits(self):
        self.assertEqual(Primes.min_bits(), 128)

    def test_primes_max_bytes(self):
        self.assertEqual(Primes.max_bytes(), 1024)

    def test_primes_min_bytes(self):
        self.assertEqual(Primes.min_bytes(), 16)

    def test_primes_encode(self):
        bts = Primes.encode(1633902946)
        self.assertEqual(bts, b'YWNhYg==\n')

    def test_primes_decode(self):
        num = Primes.decode(b'YWNhYg==')
        self.assertEqual(num, 1633902946)

    def test_primes_get(self):
        self.assertEqual(Primes.get(128), 340282366920938463463374607431768211507)
        self.assertEqual(Primes.get(0), None)
        for key in Primes._PRIMES:
            self.assertIsInstance(Primes.get(key), int)

    def test_primes_get_closest(self):
        num = Primes.get_closest(bits=7)
        self.assertEqual(num, 340282366920938463463374607431768211507)
        num = Primes.get_closest(bits=8193)
        self.assertIsNone(num)
        num = Primes.get_closest(num=1000)
        self.assertEqual(num, 340282366920938463463374607431768211507)
        num = Primes.get_closest(num=num + 1)
        self.assertEqual(
            num,
            115792089237316195423570985008687907853269984665640564039457584007913129640233  # noqa: E501
        )
        num = Primes.get(Primes.max_bits()) + 1
        self.assertIsNone(Primes.get_closest(num=num))

    def test_primes_get_closest_bits(self):
        self.assertEqual(Primes.get_closest_bits(bits=0), 128)
        self.assertEqual(Primes.get_closest_bits(bits=16), 128)
        self.assertIsNone(Primes.get_closest_bits(bits=Primes.max_bits() + 1))
        self.assertEqual(Primes.get_closest_bits(num=1234), 128)
        self.assertIsNone(Primes.get_closest_bits(num=Primes.biggest() * 2))

    def test_primes_random_int(self):
        for bits in Primes._PRIMES.keys():
            num = Primes.random_int(bits)
            prime = Primes.get_closest(bits=bits)
            self.assertIsInstance(num, int)
            self.assertLess(num, prime)
            self.assertLessEqual(num.bit_length(), bits)

    def test_primes_random_bytes(self):
        bts = Primes.random_bytes(128)
        num = int.from_bytes(bts, 'big', signed=False)
        prime = Primes.get_closest(bits=128)
        self.assertIsInstance(bts, bytes)
        self.assertLess(num, prime)


class TestInvalidInputs(TestCase):

    def test_random_int(self):
        # Few bits
        self.assertRaises(ValueError, Primes.random_int, 127)
        # Too many bits
        self.assertRaises(ValueError, Primes.random_int, 8193)
