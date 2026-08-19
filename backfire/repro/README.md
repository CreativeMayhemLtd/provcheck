# Backfire — reproduce our work

Three small scripts that check the claims in the top-level [README](../README.md) and
[LIMITS](../LIMITS.md) for yourself. Two of them need nothing but numpy and pillow; the
third needs a GPU to run the diffusion attack. We left you the tools to check our work;
we did not, and will not, ship a turnkey provenance stripper.

## What each script shows

| script | needs | shows |
| --- | --- | --- |
| `demo_amplify.py` | GPU + [embed deps](../requirements.txt) | embed a mark, run a diffusion regeneration attack, watch the keyed identifier read back **stronger** |
| `notch_limit.py` | numpy + pillow | the honest weakness: an aggressive band-notch **strips** the linear mark |
| `tripwire_dilemma.py` | numpy + pillow | the answer: that notch is **loud**, so the tamper tripwire catches it |

## Run it

Numpy-only, on a marked image (the bundled sample is already marked with the demo key):

```
python notch_limit.py      --image sample_marked.png --key "backfire-demo-key"
python tripwire_dilemma.py --image sample_marked.png --key "backfire-demo-key"
```

End to end on any image of your own (embeds first, so it is GPU-bound and slow):

```
python demo_amplify.py --image your_photo.jpg --key "your-secret-key" --serial 0x7
```

`demo_amplify.py` writes a `demo.png` like [`demo_result.png`](demo_result.png): the
original, the marked copy (invisible, same picture), and the image after a stock
`diffusers` img2img regeneration, with the confidence meter growing across the three.

## The one number that matters

`demo_result.png` also shows the control: the *same* attacked image, read with a **wrong
key**, scores near zero. The high read is your key finding your mark, not a changed image
reading high. The mark lives in the key, not the picture. That is why publishing the whole
algorithm costs us nothing (see the top-level README on Kerckhoffs's principle).

## A note on the image and the attack

The demo runs at 512px, Stable Diffusion 2.1's native resolution, on a densely textured
image. A diffusion regeneration still visibly reworks large *flat* regions of any image (a
plain sky or a sheet of water hallucinates into texture, because SD's VAE reconstructs flat
areas poorly), so the sample is a forest floor with detail edge to edge. The subtle changes
you see after the attack are the regeneration doing its work, not the mark; the wrong-key
control above is there precisely so you do not have to take that on faith.

## The sample image

`sample.png` is a 512x512 crop of *Autumn ground* by Greg Zaal (Poly Haven), redistributed
under the **CC0 1.0 Universal** public domain dedication via
[Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Autumn_ground_%E2%80%93_Panorama_(Greg_Zaal_via_Poly_Haven).jpg).
`sample_marked.png` is that image with the demo mark embedded (key `backfire-demo-key`,
serial `0x7`, 512px).
