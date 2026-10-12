//! Capability registry — the static catalogue of every provenance /
//! watermark / detector format provcheck knows how to look for, and the
//! machinery to turn it into a per-asset checklist ([`Report::checks`]).
//!
//! This is the "spine" of the lean multi-format reader: the registry is the
//! single source of truth for *what can be checked*, independent of what a
//! given build compiled in or what a given machine has installed. The verify
//! pipeline walks it once per asset to produce a baseline checklist (every
//! applicable format marked `NotChecked`, everything else `NotApplicable`),
//! then synthesis upgrades individual rows to `Present` / `Absent` /
//! `Tampered` / `NotInstalled` / `Error` as C2PA verification, the watermark
//! detectors, keyed shell-outs, and install-state resolution run.
//!
//! [`Report::checks`]: crate::report::Report::checks

use crate::report::{CheckStatus, FormatCheck, FormatId, Media};

/// Licensing / distribution tier of a format. Honest metadata for the
/// checklist: a `NotInstalled` row can tell the user whether enabling it is
/// a free download or a paid DLC, and it keeps the FOSS/BUSL boundary
/// visible at the data-model layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tier {
    /// Permissively-licensed, ships in / installable into the FOSS core.
    Foss,
    /// Paid Creative Mayhem DLC pack.
    Dlc,
    /// BUSL-licensed keyed mark — a standalone binary read via shell-out,
    /// never linked into the Apache core.
    Busl,
}

/// One entry in the capability registry: static facts about a format that
/// never change per asset. Per-asset outcome lives in [`FormatCheck`].
#[derive(Debug, Clone, Copy)]
pub struct FormatSpec {
    /// The format this entry describes.
    pub id: FormatId,
    /// Media modalities the format applies to. A format is *applicable* to
    /// an asset when this set intersects the asset's detected media.
    pub media: &'static [Media],
    /// Whether checking this format needs a downloadable model / weights
    /// (and can therefore be in a `NotInstalled` state). Deterministic
    /// checks (C2PA, soft-binding read, SynthID-text's pure algorithm) are
    /// always available in the core and set this `false`.
    pub needs_weights: bool,
    /// Licensing / distribution tier.
    pub tier: Tier,
    /// Operator-facing hint for how to enable the format when it is not
    /// installed. `None` for always-available core checks.
    pub install_hint: Option<&'static str>,
}

const A: Media = Media::Audio;
const I: Media = Media::Image;
const V: Media = Media::Video;
const T: Media = Media::Text;

/// The complete capability registry. Every [`FormatId`] variant MUST appear
/// exactly once (enforced by a unit test). Adding a format = a `FormatId`
/// variant + one row here.
pub const REGISTRY: &[FormatSpec] = &[
    FormatSpec {
        id: FormatId::C2pa,
        media: &[I, V, A],
        needs_weights: false,
        tier: Tier::Foss,
        install_hint: None,
    },
    FormatSpec {
        id: FormatId::SoftBinding,
        media: &[I, V, A],
        needs_weights: false,
        tier: Tier::Foss,
        install_hint: None,
    },
    FormatSpec {
        id: FormatId::DidAttestation,
        media: &[I, V, A],
        needs_weights: false,
        tier: Tier::Foss,
        install_hint: None,
    },
    FormatSpec {
        id: FormatId::SilentCipher,
        media: &[A],
        needs_weights: true,
        tier: Tier::Foss,
        install_hint: Some("provcheck --install silent_cipher"),
    },
    FormatSpec {
        id: FormatId::AudioSeal,
        media: &[A],
        needs_weights: true,
        tier: Tier::Foss,
        install_hint: Some("provcheck --install audio_seal"),
    },
    FormatSpec {
        id: FormatId::WavMark,
        media: &[A],
        needs_weights: true,
        tier: Tier::Foss,
        install_hint: Some("provcheck --install wav_mark"),
    },
    FormatSpec {
        id: FormatId::TrustMark,
        media: &[I],
        needs_weights: true,
        tier: Tier::Foss,
        install_hint: Some("provcheck --install trust_mark"),
    },
    FormatSpec {
        id: FormatId::TrustMarkVideo,
        media: &[V],
        needs_weights: true,
        tier: Tier::Foss,
        install_hint: Some("provcheck --install trust_mark_video"),
    },
    FormatSpec {
        id: FormatId::VideoSeal,
        media: &[V],
        needs_weights: true,
        tier: Tier::Foss,
        install_hint: Some("provcheck --install video_seal"),
    },
    FormatSpec {
        id: FormatId::PixelSeal,
        media: &[I],
        needs_weights: true,
        tier: Tier::Foss,
        install_hint: Some("provcheck --install pixel_seal"),
    },
    FormatSpec {
        id: FormatId::SynthIdText,
        media: &[T],
        needs_weights: false,
        tier: Tier::Foss,
        install_hint: None,
    },
    FormatSpec {
        id: FormatId::SynthIdImage,
        media: &[I],
        needs_weights: true,
        tier: Tier::Dlc,
        install_hint: Some("SynthID image detection — access gated (join the waitlist)"),
    },
    FormatSpec {
        id: FormatId::SynthIdAudio,
        media: &[A],
        needs_weights: true,
        tier: Tier::Dlc,
        install_hint: Some("SynthID audio detection — access gated (join the waitlist)"),
    },
    FormatSpec {
        id: FormatId::SynthIdVideo,
        media: &[V],
        needs_weights: true,
        tier: Tier::Dlc,
        install_hint: Some("SynthID video detection — access gated (join the waitlist)"),
    },
    FormatSpec {
        id: FormatId::Backfire,
        media: &[I],
        needs_weights: false,
        tier: Tier::Busl,
        install_hint: Some("Backfire keyed image mark (commercial license)"),
    },
    FormatSpec {
        id: FormatId::Mellin,
        media: &[A],
        needs_weights: false,
        tier: Tier::Busl,
        install_hint: Some("Mellin keyed audio serial (commercial license)"),
    },
    FormatSpec {
        id: FormatId::AigcDetect,
        media: &[A, I, V],
        needs_weights: true,
        tier: Tier::Dlc,
        install_hint: Some("AI-content detector (paid DLC pack)"),
    },
];

impl FormatSpec {
    /// True iff this format applies to an asset whose detected media set is
    /// `asset_media` (any overlap).
    pub fn applies_to(&self, asset_media: &[Media]) -> bool {
        self.media.iter().any(|m| asset_media.contains(m))
    }
}

/// Look up a format's static spec by id.
pub fn spec(id: FormatId) -> &'static FormatSpec {
    REGISTRY
        .iter()
        .find(|s| s.id == id)
        // Registry-completeness test guarantees one entry per FormatId, so this never panics.
        .expect("every FormatId has a registry entry")
}

/// Build the baseline checklist for an asset whose detected media modalities
/// are `asset_media` (e.g. `[Video, Audio]` for an MP4 with a soundtrack).
///
/// Every registry format applicable to the asset's media becomes a
/// `NotChecked` row; formats for other media become `NotApplicable`. This is
/// the honest "nothing has run yet" skeleton. Synthesis (a later step) walks
/// this list and upgrades rows in place as detectors, C2PA verification, and
/// install-state resolution produce real outcomes.
pub fn baseline_checklist(asset_media: &[Media]) -> Vec<FormatCheck> {
    REGISTRY
        .iter()
        .map(|spec| {
            let applicable = spec.applies_to(asset_media);
            FormatCheck {
                id: spec.id,
                media: spec.media.to_vec(),
                status: if applicable {
                    CheckStatus::NotChecked
                } else {
                    CheckStatus::NotApplicable
                },
                detail: if applicable {
                    None
                } else {
                    Some("not applicable to this media type".to_string())
                },
                confidence: None,
                install_hint: spec.install_hint.map(|s| s.to_string()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every FormatId variant appears in the registry exactly once. This is
    /// the guard that keeps `spec()` panic-free and the checklist complete.
    #[test]
    fn registry_covers_every_format_id_exactly_once() {
        use FormatId::*;
        let all = [
            C2pa,
            SoftBinding,
            DidAttestation,
            SilentCipher,
            AudioSeal,
            WavMark,
            TrustMark,
            TrustMarkVideo,
            VideoSeal,
            PixelSeal,
            SynthIdText,
            SynthIdImage,
            SynthIdAudio,
            SynthIdVideo,
            Backfire,
            Mellin,
            AigcDetect,
        ];
        for id in all {
            let n = REGISTRY.iter().filter(|s| s.id == id).count();
            assert_eq!(n, 1, "{id:?} should appear exactly once, found {n}");
        }
        assert_eq!(
            REGISTRY.len(),
            all.len(),
            "registry has entries not covered by the exhaustive id list"
        );
    }

    #[test]
    fn every_registry_entry_declares_at_least_one_medium() {
        for s in REGISTRY {
            assert!(
                !s.media.is_empty(),
                "{:?} must apply to at least one medium",
                s.id
            );
        }
    }

    #[test]
    fn install_hint_present_iff_installable_or_licensed() {
        for s in REGISTRY {
            let core_available = !s.needs_weights && s.tier == Tier::Foss;
            if core_available {
                assert!(
                    s.install_hint.is_none(),
                    "{:?} is a core check and should not carry an install hint",
                    s.id
                );
            } else {
                assert!(
                    s.install_hint.is_some(),
                    "{:?} needs weights or is DLC/BUSL and must carry an install hint",
                    s.id
                );
            }
        }
    }

    #[test]
    fn baseline_marks_wrong_media_not_applicable() {
        let checks = baseline_checklist(&[Media::Image]);
        assert_eq!(checks.len(), REGISTRY.len());
        for c in &checks {
            let spec = spec(c.id);
            let applicable = spec.media.contains(&Media::Image);
            if applicable {
                assert_eq!(
                    c.status,
                    CheckStatus::NotChecked,
                    "{:?} applies to image, expected NotChecked",
                    c.id
                );
            } else {
                assert_eq!(
                    c.status,
                    CheckStatus::NotApplicable,
                    "{:?} does not apply to image, expected NotApplicable",
                    c.id
                );
            }
        }
    }

    #[test]
    fn baseline_handles_multimodal_asset() {
        let checks = baseline_checklist(&[Media::Video, Media::Audio]);
        let status_of = |id: FormatId| checks.iter().find(|c| c.id == id).unwrap().status;
        assert_eq!(status_of(FormatId::VideoSeal), CheckStatus::NotChecked);
        assert_eq!(status_of(FormatId::SilentCipher), CheckStatus::NotChecked);
        assert_eq!(status_of(FormatId::Mellin), CheckStatus::NotChecked);
        assert_eq!(status_of(FormatId::SynthIdText), CheckStatus::NotApplicable);
        assert_eq!(status_of(FormatId::C2pa), CheckStatus::NotChecked);
    }

    #[test]
    fn baseline_carries_install_hint_on_applicable_uninstalled_rows() {
        let checks = baseline_checklist(&[Media::Image]);
        let trustmark = checks.iter().find(|c| c.id == FormatId::TrustMark).unwrap();
        assert_eq!(trustmark.status, CheckStatus::NotChecked);
        assert!(
            trustmark.install_hint.is_some(),
            "an applicable weight-backed format should carry its install hint"
        );
    }

    #[test]
    fn spec_lookup_round_trips() {
        assert_eq!(spec(FormatId::TrustMark).id, FormatId::TrustMark);
        assert_eq!(spec(FormatId::TrustMark).media, &[Media::Image]);
        assert!(spec(FormatId::Backfire).tier == Tier::Busl);
    }
}
