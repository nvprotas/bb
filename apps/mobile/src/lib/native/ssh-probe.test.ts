import { describe, expect, it, vi } from "vitest";
import { createTunnelProbeFetch, SSH_TUNNEL_SECRET_HEADER } from "./ssh-probe";

function okResponse(): Response {
  return new Response("{}", { status: 200 });
}

describe("createTunnelProbeFetch", () => {
  it("sends the tunnel secret alongside existing headers", async () => {
    const fetchImpl = vi.fn(async (_url: unknown, _init?: RequestInit) =>
      okResponse(),
    );
    const probe = createTunnelProbeFetch(
      "secret-1",
      new AbortController().signal,
      fetchImpl as unknown as typeof fetch,
    );
    await probe("http://127.64.0.1:38886/health", {
      headers: { "x-other": "1" },
    });
    const init = fetchImpl.mock.calls[0]?.[1];
    expect(init?.headers).toEqual({
      "x-other": "1",
      [SSH_TUNNEL_SECRET_HEADER]: "secret-1",
    });
  });

  it("aborts the request when the attempt is cancelled", async () => {
    const attempt = new AbortController();
    const fetchImpl = vi.fn(
      (_url: unknown, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(new Error("aborted")),
          );
        }),
    );
    const probe = createTunnelProbeFetch(
      "s",
      attempt.signal,
      fetchImpl as unknown as typeof fetch,
    );
    const pending = probe("http://127.64.0.1:38886/health", { headers: {} });
    attempt.abort();
    await expect(pending).rejects.toThrow("aborted");
  });
});
