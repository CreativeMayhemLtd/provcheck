# provcheck-mellin licensing

Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt). All rights reserved.

provcheck-mellin is **source-available and dual-licensed**. You may use it under
either:

1. **Business Source License 1.1 (BUSL-1.1)** — see `LICENSE`. This is the
   default. Under it you may freely copy, study, modify, redistribute, and make
   **non-commercial** production use of provcheck-mellin. Personal use, academic
   research, teaching, evaluation, security research, and non-profit use are
   covered. BUSL includes a **Change Date** on which the license automatically
   converts to an open-source Change License. For each released version of
   provcheck-mellin the Change Date is **four years from that version's first
   public distribution**, and the Change License is the **GNU Affero General
   Public License v3.0 or later**: an aged version opens as hard copyleft, so
   derivatives and hosted services built on it must publish their source.

2. **A commercial license** — required for any commercial or for-profit
   production use before the Change Date (embedding provcheck-mellin in a paid
   product or service, hosting it for a fee, or otherwise using it to generate
   revenue). The commercial license is offered separately by the copyright
   holder, Creative Mayhem UG (haftungsbeschränkt), as a revenue product.
   Contact licensing@creativemayhem.com (legal matters:
   legal@creativemayhem.com).

Commercial use that is already authorized under a Creative Mayhem product
license, including raidio.bot, vAIdeo.bot, is covered by that
product's own license and needs no separate grant.

Each source file carries the SPDX identifier
`BUSL-1.1 OR LicenseRef-provcheck-mellin-Commercial`, which states this choice
precisely: you take the file under BUSL-1.1 (non-commercial), or under a
commercial license from the copyright holder.

Using provcheck-mellin, whether as distributed software or as a hosted
service, is also subject to the shared keyed-forensic-tools end-user terms in
`EULA.md` and, for any hosted offering, `TOS.md` (one shared document set; the
same terms ship with Backfire). Those terms sit on top of the license above;
they do not narrow the rights the license grants, they add the acceptable-use
and no-warranty terms that govern operation.

## Relationship to the rest of provcheck

provcheck's core is Apache-2.0, and `WATERMARK_LICENSE_POLICY.md` requires
everything bundled into the shipped binary to be permissively licensed.
provcheck-mellin is the audio-side analogue of the image-side `backfire` tool,
and it uses the same BUSL-or-commercial model. It is **not** compiled into,
linked with, or shipped inside the provcheck `.exe`; provcheck invokes it as a
separate process (a shell-out), so its source-available license never reaches
the permissive binary. Apache-2.0 code may be combined into a BUSL-licensed
work, so provcheck-mellin may depend on Apache-licensed helpers; the reverse is
not permitted, so no Apache-licensed part of provcheck may depend on
provcheck-mellin.

## Why BUSL rather than a permissive or plain-copyleft license

provcheck-mellin is a frontier forensic-watermark channel (keyed, scale- and
stretch-invariant, collusion-resistant), and Creative Mayhem sells commercial
licenses for it as a revenue product. BUSL keeps the full method open and
reproducible, so anyone can verify our claims and limits, lets non-commercial
users run it freely, and reserves commercial production use for paying
customers, while still committing each released version to convert to an
open-source license four years after its first public distribution. The
permissive Apache core still gives the broader provcheck ecosystem its
low-friction path to ubiquity; provcheck-mellin, as the frontier piece, is held
under BUSL until it opens.
