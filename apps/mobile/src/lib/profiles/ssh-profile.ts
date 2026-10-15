export function sshServerUrl(hostname: string, port: number): string {
  const host = hostname.includes(":") ? `[${hostname}]` : hostname;
  return `ssh://${host}:${port}`;
}

export function sshLoopbackAddress(sequence: number): string {
  if (
    !Number.isInteger(sequence) ||
    sequence < 1 ||
    sequence >= 64 * 65536 - 1
  ) {
    throw new Error("SSH profile address space exhausted");
  }
  return `127.${64 + Math.floor(sequence / 65536)}.${Math.floor(sequence / 256) % 256}.${sequence % 256}`;
}
