import type { ProbeFetch } from "../profiles/probe";

export const SSH_TUNNEL_SECRET_HEADER = "X-BB-Tunnel-Secret";

export function createTunnelProbeFetch(
  secret: string,
  attemptSignal: AbortSignal,
  fetchImpl: typeof fetch,
): ProbeFetch {
  return async (url, init) => {
    const combined = new AbortController();
    const cancel = () => combined.abort();
    attemptSignal.addEventListener("abort", cancel, { once: true });
    init.signal?.addEventListener("abort", cancel, { once: true });
    if (attemptSignal.aborted || init.signal?.aborted) cancel();
    try {
      return await fetchImpl(url, {
        ...init,
        headers: { ...init.headers, [SSH_TUNNEL_SECRET_HEADER]: secret },
        signal: combined.signal,
      });
    } finally {
      attemptSignal.removeEventListener("abort", cancel);
      init.signal?.removeEventListener("abort", cancel);
    }
  };
}
