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

from secretshare.tests.constants import WRONGTYPES_INT, WRONGTYPES_STR,\
    WRONGTYPES_BYTES, WRONGTYPES, WRONGTYPES_STR_BYTES
from secretshare.secretshare import Primes, Secret, Share, SecretShare


class TestValidInputs(TestCase):

    def test_primes_max_bits(self):
        self.assertEqual(Primes.max_bits(), 512)

    def test_primes_max_bytes(self):
        self.assertEqual(Primes.max_bytes(), 512 // 8)

    def test_primes_get(self):
        self.assertEqual(Primes.get(8), 257)

    def test_secret_init(self):
        secret = Secret(b'acab')
        self.assertEqual(secret.value, b'acab')

    def test_secret_value(self):
        secret = Secret
        secret.value = b'acab'
        self.assertEqual(secret.value, b'acab')

    def test_secret_random(self):
        rand = Secret.random()
        self.assertIsInstance(rand, bytes)
        self.assertTrue(bool(rand))

    def test_secret_index(self):
        secret = Secret(b'\x02')
        lst = ['a', 'b', 'c', 'd']
        self.assertEqual(lst[secret], 'c')

    def test_share_init(self):
        share = Share(2, b'acab')
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, b'acab')

    def test_share_value(self):
        share = Share
        share.value = b'acab'
        self.assertEqual(share.value, b'acab')

    def test_share_point(self):
        share = Share
        share.point = 5
        self.assertEqual(share.point, 5)

    def test_share_get_max_point(self):
        share = Share
        self.assertEqual(share._get_max_point(), 511)

    def test_share_get_max_point_bytes_len(self):
        share = Share
        self.assertEqual(share._get_max_point_bytes_len(), 2)

    def test_share_bytes(self):
        share = Share(2, b'acab')
        self.assertEqual(bytes(share), b'\x02\x00acab')

    def test_share_int(self):
        share = Share(2, b'acab')
        self.assertEqual(int(share), 2200657158498)

    def test_share_str(self):
        share = Share(2, b'acab')
        self.assertEqual(str(share), 'AgBhY2Fi')

    def test_share_hex(self):
        share = Share(2, b'acab')
        # if I apply hex() directly, the test fails strangely
        self.assertEqual(share.__hex__(), '0x20061636162')

    def test_share_oct(self):
        share = Share(2, b'acab')
        # if I apply oct() directly, the test fails strangely
        self.assertEqual(share.__oct__(), '0o40014130660542')

    def test_share_to_base64(self):
        share = Share(2, b'acab')
        self.assertEqual(share.to_base64(), b'AgBhY2Fi\n')

    def test_share_len(self):
        share = Share(2, b'acab')
        self.assertEqual(len(share), 6)

    def test_share_index(self):
        share = Share(2, b'')
        lst = ['a', 'b', 'c', 'd']
        self.assertEqual(lst[share], 'c')

    def test_share_from_int(self):
        share = Share()
        share.from_int(2200657158498)
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, b'acab')

    def test_share_from_hex(self):
        share = Share()
        share.from_hex('0x20061636162')
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, b'acab')

    def test_share_from_base64(self):
        share = Share()
        share.from_base64('AgBhY2Fi')
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, b'acab')

    def test_secretshare_init(self):
        secret = Secret(b'acab')
        threshold = 2
        share_count = 3
        shamir = SecretShare(threshold, share_count, secret)
        self.assertEqual(shamir.threshold, threshold)
        self.assertEqual(shamir.share_count, share_count)
        self.assertEqual(shamir.secret.value, secret.value)

    def test_secretshare_get_random_int(self):
        shamir = SecretShare()
        self.assertIsInstance(shamir._get_random_int(), int)
        self.assertTrue(shamir._get_random_int())

    def test_secretshare_setters_getters(self):
        shamir = SecretShare()
        shamir.threshold = 5
        self.assertEqual(shamir.threshold, 5)
        shamir.share_count = 7
        self.assertEqual(shamir.share_count, 7)
        shamir.secret = Secret(b'acab')
        self.assertEqual(shamir.secret.value, b'acab')
        s1 = Share(1, b'acab')
        s2 = Share(2, b'baca')
        shamir.shares = [s1, s2]
        self.assertEqual(bytes(shamir.shares[0]), bytes(s1))
        self.assertEqual(bytes(shamir.shares[1]), bytes(s2))
        self.assertEqual(shamir.prime, 4294967311)
        poly = shamir.poly
        self.assertEqual(poly[0], 1633902946)
        for p in poly:
            self.assertIsInstance(p, int)
        self.assertEqual(len(poly), 5)
        self.assertEqual(shamir.max_share_count, 31)

    def test_secretshare_split(self):
        secret = Secret(b'acab')
        shamir = SecretShare(2, 3, secret)
        shares = shamir.split()
        self.assertEqual(len(shares), 3)
        for share in shares:
            self.assertIsInstance(share, Share)
            self.assertTrue(share)

    def test_secretshare_combine(self):
        shares_int = [1101130976934, 2200628050922, 3300125124910]
        shamir = SecretShare(2, 3)
        shamir.shares = []
        for share_int in shares_int[:2]:
            share = Share()
            share.from_int(share_int)
            shamir.shares.append(share)
        shamir.combine()
        self.assertEqual(shamir.secret.value, b'acab')
        shamir.shares = []
        for share_int in shares_int[1:]:
            share = Share()
            share.from_int(share_int)
            shamir.shares.append(share)
        shamir.combine()
        self.assertEqual(shamir.secret.value, b'acab')


class TestInvalidInputs(TestCase):

    def test_secret_value(self):
        secret = Secret()
        for wrongtype in WRONGTYPES_BYTES:
            with self.assertRaises(TypeError):
                secret.value = wrongtype
        with self.assertRaises(ValueError):
            secret.value = b''
        with self.assertRaises(ValueError):
            secret.value = b'\x00\x01'
        max_bytes = Primes.max_bytes()
        with self.assertRaises(ValueError):
            secret.value = b'aca' + b'b' * max_bytes

    def test_secret_from_bytes(self):
        secret = Secret()
        for wrongtype in WRONGTYPES_BYTES:
            self.assertRaises(TypeError, secret.from_bytes, wrongtype)

    def test_share_value(self):
        share = Share()
        for wrongtype in WRONGTYPES_BYTES:
            with self.assertRaises(TypeError):
                share.value = wrongtype

    def test_share_point(self):
        share = Share()
        for wrongtype in WRONGTYPES_INT:
            with self.assertRaises(TypeError):
                share.point = wrongtype
        with self.assertRaises(ValueError):
            share.point = 0
        max_point = Primes.max_bits() - 1
        with self.assertRaises(ValueError):
            share.point = max_point + 1

    def test_share_from_bytes(self):
        share = Share()
        for wrongtype in WRONGTYPES_BYTES:
            self.assertRaises(TypeError, share.from_bytes, wrongtype)

    def test_share_from_hex(self):
        share = Share()
        for wrongtype in WRONGTYPES_STR:
            self.assertRaises(TypeError, share.from_hex, wrongtype)

    def test_share_from_base64(self):
        share = Share()
        for wrongtype in WRONGTYPES_STR_BYTES:
            self.assertRaises(TypeError, share.from_base64, wrongtype)

    def test_share_from_int(self):
        share = Share()
        for wrongtype in WRONGTYPES_INT:
            self.assertRaises(TypeError, share.from_int, wrongtype)

    def test_secretshare_setters_getters(self):
        shamir = SecretShare()
        for wrongtype in WRONGTYPES_INT:
            with self.assertRaises(TypeError):
                shamir.threshold = wrongtype
            with self.assertRaises(TypeError):
                shamir.share_count = wrongtype
        for wrongtype in WRONGTYPES:
            with self.assertRaises(TypeError):
                shamir.secret = wrongtype
            with self.assertRaises(TypeError):
                shamir.shares = wrongtype
        with self.assertRaises(ValueError):
            shamir.threshold = 0
        with self.assertRaises(ValueError):
            shamir.share_count = 1

    def test_secretshare_split(self):
        shamir = SecretShare()
        # share_count > max
        max_count = Primes.max_bits() - 1
        shamir.share_count = max_count + 1
        self.assertRaises(ValueError, shamir.split)
        # threshold > share_count
        shamir.threshold = 3
        shamir.share_count = 2
        self.assertRaises(ValueError, shamir.split)

    def test_secretshare_combine(self):
        shamir = SecretShare()
        # len(shares) < 2
        shamir.shares = []
        self.assertRaises(ValueError, shamir.combine)
        # len(shares) > share_count
        shamir.share_count = 2
        shamir.shares = [Share() for _ in range(shamir.share_count + 1)]
        self.assertRaises(ValueError, shamir.combine)
