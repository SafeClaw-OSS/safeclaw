/**
 * SHA-256 over a byte buffer. Thin wrapper over the platform's WebCrypto.
 */
export async function sha256(data) {
    // `crypto.subtle` is available in modern browsers and Node >= 20.
    const buf = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(buf);
}
