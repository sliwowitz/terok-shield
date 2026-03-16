# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Generate the integration test map page for MkDocs."""

from pathlib import Path

import mkdocs_gen_files
from mkdocs_terok.test_map import TestMapConfig, generate_test_map

config = TestMapConfig(
    root=Path(__file__).resolve().parent.parent,
    dir_order=[
        "setup",
        "launch",
        "blocking",
        "allow_deny",
        "dns",
        "observability",
        "safety",
        "cli",
    ],
    show_markers=True,
)
with mkdocs_gen_files.open("test_map.md", "w") as f:
    f.write(generate_test_map(config=config))
