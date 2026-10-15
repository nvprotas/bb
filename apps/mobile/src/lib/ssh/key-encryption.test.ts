import { describe, expect, it } from "vitest";
import { isSshPrivateKeyEncrypted } from "./key-encryption";

function u32(value: number): number[] {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ];
}

function openSshKey(cipher: string): string {
  const bytes = [
    ...new TextEncoder().encode("openssh-key-v1\0"),
    ...u32(cipher.length),
    ...new TextEncoder().encode(cipher),
    ...u32(4),
    ...new TextEncoder().encode("none"),
    ...u32(0),
    ...u32(1),
  ];
  const body = btoa(String.fromCharCode(...bytes)).replace(/(.{70})/g, "$1\n");
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${body}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

describe("isSshPrivateKeyEncrypted", () => {
  it("reads the OpenSSH cipher name", () => {
    expect(isSshPrivateKeyEncrypted(openSshKey("none"))).toBe(false);
    expect(isSshPrivateKeyEncrypted(openSshKey("aes256-ctr"))).toBe(true);
    expect(
      isSshPrivateKeyEncrypted(openSshKey("none").replace(/\n/g, "\r\n")),
    ).toBe(false);
  });

  it("rejects an OpenSSH key with a bad magic or truncated body", () => {
    const bad = `-----BEGIN OPENSSH PRIVATE KEY-----\n${btoa("not-a-key-at-all")}\n-----END OPENSSH PRIVATE KEY-----`;
    expect(() => isSshPrivateKeyEncrypted(bad)).toThrow(/damaged/);
    const truncated = `-----BEGIN OPENSSH PRIVATE KEY-----\n${btoa("openssh-key-v1\0\0\0")}\n-----END OPENSSH PRIVATE KEY-----`;
    expect(() => isSshPrivateKeyEncrypted(truncated)).toThrow(/damaged/);
  });

  it("detects legacy PEM encryption headers", () => {
    const encrypted =
      "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCD\n\nAAAA\n-----END RSA PRIVATE KEY-----";
    const plain =
      "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----";
    expect(isSshPrivateKeyEncrypted(encrypted)).toBe(true);
    expect(isSshPrivateKeyEncrypted(plain)).toBe(false);
  });

  it("detects PKCS#8 keys", () => {
    expect(
      isSshPrivateKeyEncrypted(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----",
      ),
    ).toBe(true);
    expect(
      isSshPrivateKeyEncrypted(
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
      ),
    ).toBe(false);
  });

  it("detects PuTTY encryption", () => {
    const putty = (encryption: string) =>
      `PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: ${encryption}\nComment: k\nPublic-Lines: 1\nAAAA`;
    expect(isSshPrivateKeyEncrypted(putty("none"))).toBe(false);
    expect(isSshPrivateKeyEncrypted(putty("aes256-cbc"))).toBe(true);
  });

  it("rejects unrecognized formats", () => {
    expect(() => isSshPrivateKeyEncrypted("ssh-ed25519 AAAA user")).toThrow(
      /Unrecognized/,
    );
    expect(() =>
      isSshPrivateKeyEncrypted(
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
      ),
    ).toThrow(/Unrecognized/);
  });
});
