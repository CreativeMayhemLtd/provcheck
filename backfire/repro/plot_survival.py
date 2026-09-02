#!/usr/bin/env python3
"""Plot the Backfire image-mark survival chart from a validation results file.

Reads a JSONL of per-image verdicts (one record per photo, each a set of
pass/fail booleans for the attack battery) and writes a survival-rate bar
chart. Every bar is recomputed from the raw records, so the picture is exactly
what the reader reported, not a transcribed summary.

    python plot_survival.py                      # uses survival_200.jsonl, writes survival_200.png
    python plot_survival.py my_results.jsonl out.png

Record shape (see survival_200.jsonl):
    {"img": "000000000139", "verdicts": {"self_read": true, "zhao_diff_matched": true, ...}}
"""
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).parent
SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "survival_200.jsonl"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "survival_200.png"

recs = [json.loads(line) for line in SRC.read_text().splitlines() if line.strip()]
N = len(recs)


def rate(key):
    return 100.0 * sum(1 for r in recs if r["verdicts"].get(key)) / N


wrongkey = rate("wrong_key_rejected")

# (label, verdict key, group) in display order; group sets the colour.
BARS = [
    ("Diffusion regeneration — matched model", "zhao_diff_matched", "removal"),
    ("Diffusion regeneration — held-out model", "zhao_diff_heldout", "removal"),
    ("Neural codec — bmshj q1", "zhao_vae_bmshj_q1", "removal"),
    ("Neural codec — bmshj q3", "zhao_vae_bmshj_q3", "removal"),
    ("Neural codec — cheng q1", "zhao_vae_cheng_q1", "removal"),
    ("Neural codec — mbt q1", "zhao_vae_mbt_q1", "removal"),
    ("Neural codec — iterated ×2 (hardest)", "vae_iter_cheng_x2", "weak"),
    ("JPEG q50", "benign_jpeg50", "benign"),
    ("JPEG q90", "benign_jpeg90", "benign"),
    ("Downscale ½", "benign_resize", "benign"),
    ("Blur", "benign_blur", "benign"),
]
COL = {"removal": "#2f6f8f", "benign": "#8fb8c9", "weak": "#d98a2b"}

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 13})
fig, ax = plt.subplots(figsize=(13.4, 8.2), dpi=110)
fig.patch.set_facecolor("white")

rows = [(lbl, rate(key), grp) for lbl, key, grp in BARS][::-1]
labels = [r[0] for r in rows]
vals = [r[1] for r in rows]
cols = [COL[r[2]] for r in rows]
y = range(len(labels))
ax.barh(y, vals, color=cols, height=0.62, zorder=3)
ax.set_yticks(list(y))
ax.set_yticklabels(labels)
ax.set_xlim(0, 108)
ax.set_xticks([0, 25, 50, 75, 100])
ax.set_xlabel(f"keyed serial recovered  (% of {N} photos, read through the shipped reader)")
for i, v in enumerate(vals):
    ax.text(v + 1.2, i, f"{v:.1f}%", va="center", ha="left", fontsize=12, color="#333", zorder=4)
ax.axvline(100, color="#cccccc", lw=1, ls="--", zorder=1)
for spine in ("top", "right"):
    ax.spines[spine].set_visible(False)
ax.spines["left"].set_color("#bbb")
ax.spines["bottom"].set_color("#bbb")
ax.set_axisbelow(True)
ax.xaxis.grid(True, color="#eee", zorder=0)

fig.suptitle(
    f"Backfire image mark — survival across {N} photos",
    x=0.045, ha="left", fontsize=20, fontweight="bold", color="#1c1c1c", y=0.975,
)
ax.set_title(
    "The keyed identifier read back valid after each attack, at the reader's default threshold.",
    loc="left", fontsize=12.5, color="#555", pad=12,
)
fig.text(
    0.045, 0.026,
    f"0 false positives over {N} marked + 1,000 unmarked  •  wrong key rejected "
    f"{wrongkey:.0f}%  •  does not survive clean-noise regeneration (CtrlRegen)",
    fontsize=10.5, color="#444",
)
plt.subplots_adjust(left=0.315, right=0.975, top=0.86, bottom=0.115)
plt.savefig(OUT, facecolor="white")
print(f"wrote {OUT} from {N} records")
