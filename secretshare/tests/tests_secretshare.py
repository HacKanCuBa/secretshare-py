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

from secretshare.secretshare import Primes, Secret, SecretShare, Share
from secretshare.tests.constants import WRONGTYPES, WRONGTYPES_BYTES, \
    WRONGTYPES_INT, WRONGTYPES_STR, WRONGTYPES_STR_BYTES


class TestValidInputs(TestCase):

    def test_secret_init(self):
        secret = Secret(1633902946)
        self.assertEqual(secret.value, 1633902946)

    def test_secret_value(self):
        secret = Secret()
        secret.value = 1633902946
        self.assertEqual(secret.value, 1633902946)

    def test_secret_random(self):
        # testing actual randomness is out of the scope
        secret1 = Secret()
        secret1.random()
        secret2 = Secret()
        secret2.random()
        self.assertNotEqual(secret1.value, secret2.value)
        self.assertLessEqual(secret1.value.bit_length(), Secret.max_bits())
        secret1.random(128)
        self.assertNotEqual(secret1, secret2)
        self.assertLessEqual(secret1.value.bit_length(), 128)

    def test_secret_bit_length(self):
        secret = Secret(1633902946)
        self.assertEqual(secret.bit_length(), 31)
        secret = Secret(1)
        self.assertEqual(secret.bit_length(), 1)

    def test_secret_str(self):
        secret = Secret(1633902946)
        self.assertEqual(str(secret), 'YWNhYg==')

    def test_secret_repr(self):
        secret = Secret(1633902946)
        self.assertEqual(repr(secret), "Secret(value=1633902946)")

    def test_secret_int(self):
        secret = Secret(1633902946)
        self.assertEqual(int(secret), 1633902946)

    def test_secret_bytes(self):
        secret = Secret(1633902946)
        self.assertEqual(bytes(secret), b'acab')
        self.assertEqual(secret.to_bytes(), b'acab')

    def test_secret_from_bytes(self):
        secret = Secret()
        secret.from_bytes(b'acab')
        self.assertEqual(secret.value, 1633902946)

    def test_secret_to_hex(self):
        secret = Secret(1633902946)
        self.assertEqual(secret.to_hex(), '61636162')

    def test_secret_from_hex(self):
        secret = Secret()
        secret.from_hex('61636162')
        self.assertEqual(secret.value, 1633902946)
        secret = Secret()
        secret.from_hex('0x61636162')
        self.assertEqual(secret.value, 1633902946)

    def test_secret_to_base64(self):
        secret = Secret(1633902946)
        self.assertEqual(secret.to_base64(), b'YWNhYg==\n')

    def test_secret_from_base64(self):
        secret = Secret()
        secret.from_base64('YWNhYg==')
        self.assertEqual(secret.value, 1633902946)
        secret = Secret()
        secret.from_base64(b'YWNhYg==\n')
        self.assertEqual(secret.value, 1633902946)

    def test_secret_max_bytes(self):
        self.assertEqual(Secret.max_bytes(), 1024)

    def test_secret_max_bits(self):
        self.assertEqual(Secret.max_bits(), 8192)

    def test_share_init(self):
        share = Share(2, 1633902946)
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, 1633902946)

    def test_share_value(self):
        share = Share()
        share.value = 1633902946
        self.assertEqual(share.value, 1633902946)

    def test_share_point(self):
        share = Share()
        share.point = 5
        self.assertEqual(share.point, 5)

    def test_share_get_max_point(self):
        self.assertEqual(Share.max_point(), 8191)

    def test_share_str(self):
        share = Share(2, 1633902946)
        self.assertEqual(str(share), 'AgBhY2Fi')

    def test_share_repr(self):
        share = Share(2, 1633902946)
        self.assertEqual(repr(share), "Share(point=2, value=1633902946)")

    def test_share_int(self):
        share = Share(2, 1633902946)
        self.assertEqual(int(share), 1633902946)

    def test_share_bytes(self):
        share = Share(2, 1633902946)
        self.assertEqual(bytes(share), b'\x02\x00acab')

    def test_share_from_bytes(self):
        share = Share()
        share.from_bytes(b'\x02\x00acab')
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, 1633902946)

    def test_share_to_hex(self):
        share = Share(2, 1633902946)
        self.assertEqual(share.to_hex(), '020061636162')

    def test_share_from_hex(self):
        share = Share()
        share.from_hex('020061636162')
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, 1633902946)
        share = Share()
        share.from_hex('0x20061636162')
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, 1633902946)
        share = Share()
        share.from_hex('20061636162')
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, 1633902946)

    def test_share_to_base64(self):
        share = Share(2, 1633902946)
        self.assertEqual(share.to_base64(), b'AgBhY2Fi\n')

    def test_share_from_base64(self):
        share = Share()
        share.from_base64('AgBhY2Fi')
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, 1633902946)
        share = Share()
        share.from_base64(b'AgBhY2Fi\n')
        self.assertEqual(share.point, 2)
        self.assertEqual(share.value, 1633902946)

    def test_share_index(self):
        share = Share(10, 1633902946)
        # hex() and oct() calls __index__()
        # noinspection PyTypeChecker
        self.assertEqual(hex(share), '0xa')
        # noinspection PyTypeChecker
        self.assertEqual(oct(share), '0o12')
        share = Share(2)
        indexable = 1, 2, 3,
        # noinspection PyTypeChecker
        self.assertEqual(indexable[share], 3)

    def test_secretshare_init(self):
        secret = Secret(1633902946)
        threshold = 2
        share_count = 3
        shares = Share(1), Share(2)
        shamir = SecretShare(threshold, share_count, secret=secret, shares=shares)
        self.assertEqual(shamir.threshold, threshold)
        self.assertEqual(shamir.share_count, share_count)
        self.assertEqual(shamir.secret, secret)
        self.assertEqual(shamir.shares, list(shares))

    def test_secretshare_setters_getters(self):
        shamir = SecretShare()
        shamir.threshold = 5
        self.assertEqual(shamir.threshold, 5)
        shamir.share_count = 7
        self.assertEqual(shamir.share_count, 7)
        shamir.secret = Secret(1633902946)
        self.assertEqual(shamir.secret.value, 1633902946)
        s1 = Share(1, 5)
        s2 = Share(2, 5)
        shamir.shares = s1, s2,
        self.assertEqual(shamir.shares[0], s1)
        self.assertEqual(shamir.shares[1], s2)
        self.assertEqual(shamir.max_share_count, 30)

    def test_secretshare_split(self):
        secret = Secret(1633902946)
        shamir = SecretShare(2, 3, secret=secret)
        shares = shamir.split()
        self.assertEqual(shares, shamir.shares)
        self.assertEqual(len(shares), 3)
        point = 1
        for share in shares:
            self.assertIsInstance(share, Share)
            self.assertEqual(share.point, point)
            point += 1

    def test_secretshare_combine(self):
        shares_int = (
            (1, 50250691263452338915556183402696678272),
            (2, 100501382526904677831112366803759453598),
            (3, 150752073790357016746668550204822228924),
        )
        secret_expected = Secret(1633902946)
        shamir = SecretShare(2, 3)
        shamir.shares = []
        for share_int in shares_int[:2]:
            share = Share(*share_int)
            shamir.shares.append(share)
        secret = shamir.combine()
        self.assertEqual(shamir.secret, secret)
        self.assertEqual(secret.value, secret_expected.value)
        shamir.shares = []
        for share_int in shares_int[1:]:
            share = Share(*share_int)
            shamir.shares.append(share)
        shamir.combine()
        self.assertEqual(shamir.secret.value, secret_expected.value)

    def test_secretshare_split_combine(self):
        secret_int = 141674243754083726050570831578464295953
        shares_int = (
            (1, 42125844484391047748301228917955063925),
            (2, 305662287504277561771218479172038047953),
            (3, 251718838971866341192573367477176825023),
            (4, 220577865808095849475740501265139606642),
            (5, 212239368012966086620719880535926392810),
            (6, 226703345586477052627511505289537183527),
        )
        threshold, share_count = 3, 6
        shamir = SecretShare(threshold, share_count)
        for index in (0, 2, 4):
            share = Share(*shares_int[index])
            shamir.shares.append(share)
        secret_recovered = shamir.combine()
        self.assertEqual(int(secret_recovered), secret_int)
        shamir = SecretShare(threshold, share_count)
        for index in (1, 3, 5):
            share = Share(*shares_int[index])
            shamir.shares.append(share)
        secret_recovered = shamir.combine()
        self.assertEqual(int(secret_recovered), secret_int)

    def test_secretshare_split_combine_all_primes_sizes(self):
        for bits in Primes._PRIMES.keys():
            if bits == 512:
                continue
            secret = Secret()
            secret.random(bits)
            shamir = SecretShare(3, 5, secret=secret)
            shamir.split()
            shamir.shares = shamir.shares[1:4]
            secret_combined = shamir.combine()
            self.assertEqual(secret_combined.value, secret.value,
                             f'Secrets differ for {bits} bits')


class TestInvalidInputs(TestCase):

    def test_secret_value(self):
        secret = Secret()
        for wrongtype in WRONGTYPES_INT:
            with self.assertRaises(TypeError):
                secret.value = wrongtype
        with self.assertRaises(ValueError):
            secret.value = 0
        with self.assertRaises(ValueError):
            secret.value = -1
        with self.assertRaises(ValueError):
            secret.value = Primes.biggest() + 1

    def test_secret_from_bytes(self):
        secret = Secret()
        for wrongtype in WRONGTYPES_BYTES:
            self.assertRaises(TypeError, secret.from_bytes, wrongtype)
        self.assertRaises(ValueError, secret.from_bytes, b'\x00')

    def test_share_value(self):
        share = Share()
        for wrongtype in WRONGTYPES_INT:
            with self.assertRaises(TypeError):
                share.value = wrongtype
        with self.assertRaises(ValueError):
            share.value = 0
        with self.assertRaises(ValueError):
            share.value = -1
        with self.assertRaises(ValueError):
            share.value = Primes.biggest() + 1

    def test_share_point(self):
        share = Share()
        for wrongtype in WRONGTYPES_INT:
            with self.assertRaises(TypeError):
                share.point = wrongtype
        with self.assertRaises(ValueError):
            share.point = 0
        with self.assertRaises(ValueError):
            share.point = Primes.max_bits()

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
        shamir = SecretShare(threshold=2, share_count=3)
        # len(shares) < threshold
        shamir.shares = []
        self.assertRaises(ValueError, shamir.combine)
        # len(shares) > share_count
        shamir.shares = [Share() for _ in range(4)]
        self.assertRaises(ValueError, shamir.combine)
