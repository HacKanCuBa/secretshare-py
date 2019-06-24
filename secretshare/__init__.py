"""Share secrets in a cryptographically secure way.

Implements Shamir's secret sharing algorithm.
"""

from .secretshare import Secret, SecretShare, Share

__version__ = '0.4.2'

__all__ = ('Secret', 'SecretShare', 'Share', '__version__')
