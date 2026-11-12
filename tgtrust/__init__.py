"""tgtrust: anonymous, accountable agents for Telegram on TON.

Author: Aleksandr Shcherbakov (@miinimal), MINIMALCULT.
"""

import warnings as _warnings

# `python -m tgtrust.telegram_sig` runs a module this package already imported; runpy would print a
# harmless RuntimeWarning, which is noise next to the one-line result of that command.
_warnings.filterwarnings(
    "ignore", message=r"'tgtrust\.telegram_sig' found in sys\.modules", category=RuntimeWarning
)

from .issuer import (
    Credential,
    Holder,
    Issuer,
    IssuanceError,
    IssuerPolicy,
    MemoryIssuedStore,
    SqliteIssuedStore,
    verify_credential,
)
from .telegram_sig import TELEGRAM_PUBLIC_KEYS, InitDataError, VerifiedInitData, verify_init_data

__all__ = [
    "Credential",
    "Holder",
    "InitDataError",
    "IssuanceError",
    "Issuer",
    "IssuerPolicy",
    "MemoryIssuedStore",
    "SqliteIssuedStore",
    "TELEGRAM_PUBLIC_KEYS",
    "VerifiedInitData",
    "verify_credential",
    "verify_init_data",
]
