import sys
from . import _lief
from ._lief import *
from ._lief import __version__, __tag__, __commit__, __is_tagged__

# cf. https://github.com/pytorch/pytorch/blob/60a3b7425dde97fe8b46183c154a9c3b24f0c733/torch/__init__.py#L467-L470
for attr in dir(_lief):
    candidate = getattr(_lief, attr)
    if type(candidate) is type(_lief):
        sys.modules.setdefault(f"lief.{attr}", candidate)


