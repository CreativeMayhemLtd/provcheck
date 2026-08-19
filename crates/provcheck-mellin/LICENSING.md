# provcheck-mellin licensing

Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt). All rights reserved.

provcheck-mellin is **dual-licensed**. You may use it under either:

1. **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)** — see
   `LICENSE`. This is the default. Under the AGPL you are free to use, study,
   modify, and redistribute provcheck-mellin, including running it as a network
   service, provided that you make your complete corresponding source code
   (including any modifications, and including the case where users interact with it
   remotely over a network) available under the same terms.

2. **A commercial license** — for organizations that want to embed, modify, or offer
   provcheck-mellin (or a derivative) without the AGPL's source-disclosure
   obligations. The commercial license is offered separately by the copyright holder,
   Creative Mayhem UG (haftungsbeschränkt). Contact licensing@creativemayhem.com
   (legal matters: legal@creativemayhem.com).

Each source file carries the SPDX identifier
`AGPL-3.0-or-later OR LicenseRef-provcheck-mellin-Commercial`, which states this choice
precisely: you may take the file under the AGPL, or under a commercial license from
the copyright holder.

## Relationship to the rest of provcheck

provcheck's core is Apache-2.0, and `WATERMARK_LICENSE_POLICY.md` requires everything
bundled into the shipped binary to be permissively licensed. provcheck-mellin is an
**opt-in** crate: it is **not** compiled into, linked with, or shipped inside the
provcheck `.exe`, so its copyleft license never reaches the permissive binary. It is
the audio-side analogue of the image-side `backfire` tool, which uses the same
AGPL-or-commercial model. Apache-2.0 code may be combined into an AGPL-3.0 work, so
provcheck-mellin may depend on the Apache-licensed helpers; the reverse is not
permitted, so no Apache-licensed part of provcheck may depend on provcheck-mellin.

## Why AGPL rather than a permissive license

provcheck-mellin is a frontier forensic-watermark channel (keyed, scale- and
stretch-invariant, collusion-resistant). AGPL keeps improvements to that mechanism in
the open: a competitor who modifies it, including behind a network service, must
publish their changes. Organizations that need to keep modifications private can take
the commercial license instead. The permissive Apache core still gives the broader
provcheck ecosystem its low-friction path to ubiquity; provcheck-mellin, as a frontier
tool, is held under copyleft.
