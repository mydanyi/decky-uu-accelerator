"""UU accelerator support package for the Decky plugin.

Public API:

* :func:`uu_accelerator.platform.detect_platform` / ``select_engine``
* :func:`uu_accelerator.payload.parse_metadata` / ``extract_payload``
* installer helpers ``fetch_metadata`` / ``download_archive``
"""

from .payload import (
    download_archive,
    extract_payload,
    fetch_metadata,
    parse_metadata,
)
from .platform import detect_platform, elf_machine, select_engine

__all__ = [
    "detect_platform",
    "elf_machine",
    "select_engine",
    "parse_metadata",
    "extract_payload",
    "fetch_metadata",
    "download_archive",
]
