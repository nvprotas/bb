const OPENSSH_MAGIC = "openssh-key-v1\0";

function decodeBase64(body: string): Uint8Array {
  const binary = atob(body.replace(/\s+/g, ""));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function openSshCipherName(body: string): string {
  const bytes = decodeBase64(body);
  const magic = new TextDecoder().decode(
    bytes.subarray(0, OPENSSH_MAGIC.length),
  );
  if (magic !== OPENSSH_MAGIC) throw new Error("Invalid OpenSSH key");
  const offset = OPENSSH_MAGIC.length;
  if (bytes.length < offset + 4) throw new Error("Invalid OpenSSH key");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const length = view.getUint32(offset);
  if (length === 0 || bytes.length < offset + 4 + length)
    throw new Error("Invalid OpenSSH key");
  return new TextDecoder().decode(
    bytes.subarray(offset + 4, offset + 4 + length),
  );
}

export function isSshPrivateKeyEncrypted(text: string): boolean {
  const key = text.replace(/\r\n?/g, "\n").trim();
  const pem =
    /^-----BEGIN ([A-Z0-9 ]+)-----\n([\s\S]*?)\n-----END \1-----$/.exec(key);
  if (pem) {
    const label = pem[1];
    const body = pem[2] ?? "";
    if (label === "OPENSSH PRIVATE KEY") {
      try {
        return openSshCipherName(body) !== "none";
      } catch {
        throw new Error("The private key file is damaged.");
      }
    }
    if (label === "ENCRYPTED PRIVATE KEY") return true;
    if (
      label === "PRIVATE KEY" ||
      label === "RSA PRIVATE KEY" ||
      label === "DSA PRIVATE KEY" ||
      label === "EC PRIVATE KEY"
    )
      return /^Proc-Type:\s*4,\s*ENCRYPTED\s*$/m.test(body);
  }
  if (/^PuTTY-User-Key-File-\d+:/.test(key)) {
    const encryption = /^Encryption:\s*(\S+)\s*$/m.exec(key);
    if (encryption) return encryption[1] !== "none";
  }
  throw new Error(
    "Unrecognized private key format. Use an OpenSSH, PEM, or PuTTY private key.",
  );
}
