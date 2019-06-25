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

"""Auxiliary prime numbers module for SecretShare."""


from binascii import a2b_base64, b2a_base64
from typing import Dict, Optional

from passphrase.random import randint

from .calc import bytes_to_int, int_to_bytes


class Primes:
    """Helper module to handle prime numbers."""

    # The following primes are the closest bigger than 2^bits-1, assuring the
    # required number of bits of security is met.
    _PRIMES: Dict[int, bytes] = {
        # Lower values are too small
        128: b'AQAAAAAAAAAAAAAAAAAAADM=',
        256: b'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEp',
        512: b'Af//////////////////////////////////////////////////////////////'
             b'////////////////////////',  # 13th Mersenne prime
        # The following primes were generated with ssh-keygen
        1024: b'w6/AZR8enj1UPxvgqHvqcwubIWZdBMkdry74x+j+qUCQuOHgAJFjDTvuDEJWwk5'
              b'K6+bYj/Iv9hB/Ol33cG64kscRcng9NsNV0HVMC/lMjuQnohqRXyOluCcMjFcFtY'
              b'RUEykr8LkrHusbXRtkV+fOh1TGZA5xyR1STftXM0YArQM=',
        2048: b'6gMD0D/2m8q9wl3epqyc/ujDbvSMfyiCtl1Wiw0Up9rM9Kbo6QVyfAuYL6TXxOW'
              b'd2vRwTQ7HZ9ebE6MkZ8jTn2FbUmjkM43XDGByxwLN9vORU8Ry5mir8LhbjQhFQC'
              b'eqUuMifFugF7JVj3phHwnHvl4opHL6tRxx/36MdYzVIFxWLzZ02UHvLex/Oz9Jx'
              b'M46nde0J1vVN78EpKjpj6pCrQoigM/A1GkjOe7IA7af3DMFeDf70jPba3iSD3BJ'
              b'tfnKnP3Zg1G555RyZUOfSEKTBtbKsId08rdCemHadXN10mwIuZvK+4CF5B26Dkn'
              b'RQu7BZMwxU6sxGft2AzszakNIvw==',
        4096: b'wofaFpLIdg2InKvqanBV+tsTyfBkyHMi1Wm5xXQAHeuhaF2o3/uaESU/aFowReL'
              b'OugV8Nd1Bf3FxEJSQB3ArJaN67mDDoamqahZnwVu///Fz3yeBOnSVl1aCKrNKK7'
              b'l7L0CMxqmUrcg/BcuAKHhLhZolAy1pHx3fsah/R+3Cif5EUr5OTXsHdFwdWpAef'
              b'vBSFGXf/B7sq35PFRcqkCV6/8oRtFWt0kBnsgwg7fm1tZvf2uA78Ks5oT5gUVyo'
              b'reMnO7yoKQ07WB+Sth8aiTq/8WJVqSJmOBWWQPeGm1wwyP/zwzeLFOGlUpyN4SC'
              b'p4gmTiOEhe938wXCPN+dL3l0KLc/cTdJ7ppfD+COBgtp8XQJDHghgZzWMyam07/'
              b'fI1/yfDIwFKIh6GUptBhOu4e7dx6MVrBoXjpN35Ij0k2dXO6jt+A/W7eLSVvBhS'
              b'vgbj7GyQ+p/BMpr4OC+n0NSXTtnGNql4v09IL4/N+1ALa/X8Zw55RpAho0/edRc'
              b'1CKp90VNs/7/IFvkwQI0kU/YiCs0Tb+1wr5bV26pTrYsOvzQEu5/gvB0S+Bnc26'
              b'aeO845vBkdOAld28TivhOQJOrNmg6YNDbXLn3XKfEMDBZ4N3OOmQaMnj1AV/ULq'
              b'p5ty5fDS79qt47drI91MKjnzWbPKAPdYS3KYALPgHcPUzUs7AWBJ8=',
        8192: b'4/y9z9QaQJxYvgg7ZIWi1n4gkxsfRpd0uuDxqyiYuAADJYGxxPxx/hNgh5N6iFr'
              b'7b8nlgt2XuN460q+GFBnV8GJ4MW36eLrn7wmYifDplXXHgS5yQLZ2I+eHdzcBOn'
              b'1ds2OAQAg0AOjydgC6wGUNJCIMobPAX7fdcEaaIB2/8TCOyhxxUqYBa7ib+2xiV'
              b'xXukakuoYSPCySRqpIYdGjZ6EQmedf19rZLydWj1Om1jFnu62X41rcKcQmeG0IL'
              b'wP11DLLzM8I8l5Zr5yemttmuyMDrJDbgF3DwOEC/7JIou23UbOJ9VznhhCn0ZP/'
              b'2gSsPZqiwAkvgMpSQC40Lw8pnhfjEGO/nBoss0ZClS7n5DgWIWlyF3AaUlcIAn3'
              b'nb/Xd019ZbmDH9wpXOFG9OuR3FarvQtkvq88NA4L8SOhFdEiidRLZQ/4Rhc0MI9'
              b'HAc8sGZZ22ztIBPzb1rCMXUh1BzrVxXXKC2RZdHKlwj60J3tSsRKPOxrjY+NqLC'
              b'1u9fzgDuFXOkCtWs3NrePiZyl5z2jodTBSCyyiwREMvktjHzq+g8/9t9Ws3W3KW'
              b'RbjCxdx/inE9gFjtiNJtmwO3c6FAvfEndQInqWuMf+yIKiMjSMjZ7Uvq3ZE8C5+'
              b'wQN4aXITzw2Q2oOplBwhfFWfiN7GWHrZU8lfEcV18O+pzAZQlVxzORDy+Qx4rjZ'
              b'/Z7D0lqEA4LAYcxQE0rrsdCD4wrH7ZhKvaezzafI23Qv7Csuu1BQbKhRZHGR1/F'
              b'w9TptiKez34ojAFdWaNd5n9jPcWGYJqzq4WgK5nd8bb6fVTUst23Z8qreXyfspW'
              b'UuAtbqs93dmbQs1zm79jkYnDE1xW3T+pk/jT79DMrtOhHfKQ4ZFwkREQX6ldptQ'
              b'eSX7S4/FnkKfHsWTw5f3EIeggLOaGStRR9BNnzDcI3dkyBDlGbdO6Q8EfQgpEEt'
              b'roaAfHMGMhb559SCE+tbXvz7aNtY5gdi3VnZ0DbGqbgatDB9qO2ZdLZ0ONj/ON7'
              b'WBxoKl9VTYIISc7nBmp9sBHqfZFrSkUhLLvHpWra0z0gO4oe2gMGSjQ1GRbCQ+Z'
              b'dRUJZdMFGimJrdztIliEIID8CgU8VZAFJvMIyXEDyRX8GGMqv3iYWIyby+B6Mcn'
              b'+v7RtD46yHUun07f9bWL0xaIK1VeYyeP6wC2EURwPAYLYYjzUo4XbpstWZZXkEi'
              b'3I+tnjNVvqXkAQnDp+I8jVATFIu0Hbp8ocJfy92AKLUVm0vbvtgCphUthzbQ2ME'
              b'DU8w2WuwEe9LsODyEZL3KxBrTzinn6OEl4w8Kpq5RTS+Acg5J7yVqcXlXmGNfF1'
              b'3qfo5Zk7vEbLVD1k5ba183CPxeUhYW9iDQu7WrGU0Sw==',
    }

    @staticmethod
    def encode(num: int) -> bytes:
        """Encode an integer number as a base64 bytes string."""
        return b2a_base64(int_to_bytes(num))

    @staticmethod
    def decode(bts: bytes) -> int:
        """Decode a base64 bytes string to an integer number."""
        return bytes_to_int(a2b_base64(bts))

    @classmethod
    def min_bits(cls) -> int:
        """Minimum amount of bits than can be processed with these primes."""
        return min(cls._PRIMES.keys())

    @classmethod
    def max_bits(cls) -> int:
        """Maximum amount of bits than can be processed with these primes."""
        return max(cls._PRIMES.keys())

    @classmethod
    def min_bytes(cls) -> int:
        """Minimum amount of bytes than can be processed with these primes."""
        return cls.min_bits() // 8

    @classmethod
    def max_bytes(cls) -> int:
        """Maximum amount of bytes than can be processed with these primes."""
        return cls.max_bits() // 8

    @classmethod
    def biggest(cls) -> int:
        """Get the biggest prime."""
        return cls.get(bits=cls.max_bits())

    @classmethod
    def get(cls, bits: int) -> Optional[int]:
        """Get a prime number for the given number of security bits, if any."""
        b64 = cls._PRIMES.get(bits)
        if b64 is None:
            return None
        return cls.decode(b64)

    @classmethod
    def get_closest(cls, *, bits: Optional[int] = None,
                    num: Optional[int] = None) -> Optional[int]:
        """Get the prime number closest bigger for the given parameters, if any.

        :param bits: Use the given number of security bits to choose the prime.
        :param num: Find a prime immediately larger than `num`.
        """
        get_bits = cls.get_closest_bits(bits=bits, num=num)
        return cls.get(get_bits)

    @classmethod
    def get_closest_bits(cls, *, bits: Optional[int] = None,
                         num: Optional[int] = None) -> Optional[int]:
        """Get the number of security bits for the closest prime bigger, if any.

        :param bits: Use the given number of security bits to choose the prime.
        :param num: Find a prime immediately larger than `num`.
        """
        if num is not None:
            get_bits = cls.get_closest_bits(bits=num.bit_length())
            if not get_bits:
                return None
            prime = cls.get(get_bits)
            if prime and prime > num:
                return get_bits
            # Choose the next prime
            return cls.get_closest_bits(bits=get_bits * 2)

        get_bits = None
        if bits is not None:
            for bts in cls._PRIMES:
                if bts >= bits:
                    get_bits = bts
                    break
        return get_bits

    @classmethod
    def random_int(cls, bits: int) -> int:
        """Generate a secure random integer for the given number of bits.

        Secure means, besides being cryptographically secure, that the integer
        number is lower than the prime closest bigger to the number of bits.
        """
        min_bits = cls.min_bits()
        if bits < min_bits:
            raise ValueError(f'bits must be bigger or equal than {min_bits}')
        max_bits = cls.max_bits()
        if bits > max_bits:
            raise ValueError(f'bits must be lower than {max_bits}')
        prime = cls.get_closest(bits=bits)
        random_number = randint(bits)
        while random_number > prime:
            random_number = randint(bits)
        return random_number

    @classmethod
    def random_bytes(cls, bits: int) -> bytes:
        """Generate secure random bytes for the given number of bits.

        Secure means, besides being cryptographically secure, that the bytes
        represent an integer number lower than the prime closest bigger to the
        number of bits.
        """
        return int_to_bytes(cls.random_int(bits))
