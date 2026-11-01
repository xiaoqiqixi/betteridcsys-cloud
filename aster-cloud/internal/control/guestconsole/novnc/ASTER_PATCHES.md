# Vendored noVNC

Upstream: [noVNC v1.7.0](https://github.com/novnc/noVNC/releases/tag/v1.7.0),
commit `63107bd06d9e1f6136ff21aeda8cd62cbf0d433e`.
`UPSTREAM.json` records the archive SHA-256, every original file digest, and the
two patched file digests. The source and applicable licences ship with the
controller and are served under `/console/novnc/`.

Two local changes support a self-only Content Security Policy:

- `core/display.js` decodes PNG/JPEG rectangles using `createImageBitmap(Blob)`
  and preserves render queue ordering, without creating a data or blob URL.
- `core/util/browser.js` selects the existing canvas cursor fallback without
  probing a data URL cursor.

The upstream MPL 2.0 licence and copyright notices apply to these modified
files. `docs/` and `vendor/pako/LICENSE` contain the licence texts. No package
manager, CDN, remote script, analytics or external font is used at runtime.
