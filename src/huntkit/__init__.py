"""Detection engineering helpers: Sigma parsing, query generation, ATT&CK coverage."""

__version__ = "0.1.0"

from .sigma import SigmaParseError, SigmaRule, load
from .querygen import render

__all__ = ["SigmaParseError", "SigmaRule", "load", "render"]
