# DLPrevent logo

- `dlprevent-logo.svg`: horizontal logo, viewBox 624 × 120. Use at 120 px wide or larger for readable lettering.
- `dlprevent-icon.svg`: symbol only, viewBox 120 × 120. Use for compact fields, app icons and favicons (16 px or larger).
- `dlprevent-emblem.svg`: square emblem on a light rounded tile, viewBox 128 × 128. Used as the dashboard browser-tab icon, with contrast on both light and dark browser chrome.

Both SVG files contain vector paths, including the lettering: no fonts or raster images are required. The original design was redrawn geometrically; the wordmark uses outlined Helvetica Neue Bold. Backgrounds are transparent; place on a light surface to preserve graphite contrast.

For web use, set `display: block; width: 100%; max-width: 100%; height: auto`. Avoid negative margins, cropping and fixed width/height combinations that distort the aspect ratio.

The dashboard uses `apps/web/src/lib/Brand.svelte`. Use `<Brand />` for the full logo or `<Brand compact />` for the 32 px symbol. Production SVG copies live in `apps/web/src/assets`.

GIMP can import either SVG at a chosen resolution; keep the SVG as the scalable master.
