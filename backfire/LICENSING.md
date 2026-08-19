# Backfire licensing

Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt). All rights reserved.

Backfire is **dual-licensed**. You may use it under either:

1. **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)** — see
   `LICENSE`. This is the default. Under the AGPL you are free to use, study,
   modify, and redistribute Backfire, including running it as a network service,
   provided that you make your complete corresponding source code (including any
   modifications, and including the case where users interact with it remotely over
   a network) available under the same terms.

2. **A commercial license** — for organizations that want to embed, modify, or offer
   Backfire (or a derivative) without the AGPL's source-disclosure obligations. The
   commercial license is offered separately by the copyright holder, Creative Mayhem
   UG (haftungsbeschränkt). Contact licensing@creativemayhem.com (legal matters:
   legal@creativemayhem.com).

Each source file carries the SPDX identifier
`AGPL-3.0-or-later OR LicenseRef-Backfire-Commercial`, which states this choice
precisely: you may take the file under the AGPL, or under a commercial license from
the copyright holder.

## Relationship to the rest of provcheck

provcheck's core is Apache-2.0, and `WATERMARK_LICENSE_POLICY.md` requires everything
bundled into the shipped binary to be permissively licensed. Backfire is a standalone
Python tool: it is **not** compiled into, linked with, or shipped inside the provcheck
`.exe`, so its copyleft license never reaches the permissive binary. This is the same
isolation `provcheck-mellin` (AGPL-3.0-or-later) uses. Apache-2.0 code may be combined into an
AGPL-3.0 work, so Backfire may depend on the Apache-licensed helpers; the reverse is
not permitted, so no Apache-licensed part of provcheck may depend on Backfire.

## Why AGPL rather than a permissive license

Backfire's value is that it survives, and inverts, the provenance-stripping attacks it
is built against. AGPL keeps improvements to that mechanism in the open: a competitor
who modifies Backfire, including behind a network service, must publish their changes.
Organizations that need to keep modifications private can take the commercial license
instead. The permissive Apache core still gives the broader provcheck ecosystem its
low-friction path to ubiquity; Backfire, as a frontier tool, is held under copyleft.
