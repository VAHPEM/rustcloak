# RustCloak premium tier — license

The files in this `premium/` directory are **dual-licensed**:

> **SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Commercial**

You may use, copy, modify and distribute them under **either**:

1. the **GNU Affero General Public License, version 3 or later** (AGPLv3+) — a strong copyleft
   license. Building a product or a **network service** on the premium tier under this option
   triggers the AGPL's source-availability obligations for your combined/derived work; **or**
2. a **commercial license** from the author, which lifts the AGPL copyleft obligations for
   proprietary / closed-source use. See [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md).

The full AGPLv3 text is at <https://www.gnu.org/licenses/agpl-3.0.txt>; vendor a copy here as
`premium/LICENSE-AGPL-3.0.txt` for an offline-complete distribution.

The project **core** (`src/`) is separately licensed under **Apache-2.0** (see the top-level
[`LICENSE`](../LICENSE)). The core never `#include`s or links the premium tier, so a core-only
build (`cmake -DRUSTCLOAK_PREMIUM=OFF`) is pure Apache-2.0.
