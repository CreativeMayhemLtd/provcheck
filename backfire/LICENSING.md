# Backfire licensing

Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt). All rights reserved.

Backfire is **source-available and dual-licensed**. You may use it under either:

1. **Business Source License 1.1 (BUSL-1.1)** — see `LICENSE`. This is the
   default. Under it you may freely copy, study, modify, redistribute, and make
   **non-commercial** production use of Backfire. Personal use, academic
   research, teaching, evaluation, security research, and non-profit use are
   covered. BUSL includes a **Change Date** on which the license automatically
   converts to an open-source Change License; that date and the target license
   are **not yet finalized** for Backfire and will be set by Creative Mayhem
   before any public release.

2. **A commercial license** — required for any commercial or for-profit
   production use before the Change Date (embedding Backfire in a paid product
   or service, hosting it for a fee, or otherwise using it to generate
   revenue). The commercial license is offered separately by the copyright
   holder, Creative Mayhem UG (haftungsbeschränkt), as a revenue product.
   Contact licensing@creativemayhem.com (legal matters:
   legal@creativemayhem.com).

Each source file carries the SPDX identifier
`BUSL-1.1 OR LicenseRef-Backfire-Commercial`, which states this choice
precisely: you take the file under BUSL-1.1 (non-commercial), or under a
commercial license from the copyright holder.

Using Backfire, whether as distributed software or as a hosted service, is also
subject to the end-user terms in `EULA.md` and, for any hosted offering,
`TOS.md`. Those terms sit on top of the license above; they do not narrow the
rights the license grants, they add the acceptable-use and no-warranty terms
that govern operation.

## Relationship to the rest of provcheck

provcheck's core is Apache-2.0, and `WATERMARK_LICENSE_POLICY.md` requires
everything bundled into the shipped binary to be permissively licensed.
Backfire is a standalone Python tool: it is **not** compiled into, linked with,
or shipped inside the provcheck `.exe`. provcheck invokes it as a separate
process (a shell-out), so its source-available license never reaches the
permissive binary. Apache-2.0 code may be combined into a BUSL-licensed work,
so Backfire may depend on Apache-licensed helpers; the reverse is not
permitted, so no Apache-licensed part of provcheck may depend on Backfire.

## Why BUSL rather than a permissive or plain-copyleft license

Backfire is a frontier forensic tool, and Creative Mayhem sells commercial
licenses for it as a revenue product. BUSL keeps the full method open and
reproducible (the `read` side needs only numpy and pillow, so anyone can verify
our claims and limits), lets non-commercial users run it freely, and reserves
commercial production use for paying customers, while still reserving a switch
to an open-source license on a future Change Date, which Creative Mayhem will
set before any public release. The permissive Apache
core still gives the broader provcheck ecosystem its low-friction path to
ubiquity; Backfire, as the frontier piece, is held under BUSL until it opens.
