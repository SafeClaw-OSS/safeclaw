# Vendored: `@sudp-protocol/authorizer`

These files are copied verbatim from npm package
`@sudp-protocol/authorizer@0.1.0` (dist/), with `//# sourceMappingURL=...`
trailers stripped. They are loaded as native ESM modules by `../main.js`.

## Why vendored

The daemon serves `/cli/auth/*` as static assets baked into the binary
(`include_str!`). We need pure-browser ESM with no build step, so we ship the
authorizer's `dist/*.js` straight from a known release. Re-vendor when
bumping `sudp` major versions:

```
SRC=/path/to/safeclaw-pro-frontend/node_modules/@sudp-protocol/authorizer/dist
for f in bytes.js canonical.js hash.js aad.js binding.js kdf.js webauthn.js; do
  cp "$SRC/$f" .
  sed -i 's|//# sourceMappingURL=.*||' "$f"
done
```

## Why not aead.js / index.js

`aead.js` pulls `@noble/ciphers` for ChaCha20-Poly1305. The CLI's
unlock/lock ceremonies don't need AEAD on the browser side (sealing happens
only during enroll/write, not here). Skipping it keeps the bundle tiny and
dependency-free.

`index.js` is just a re-export barrel — we import from each module
directly.
