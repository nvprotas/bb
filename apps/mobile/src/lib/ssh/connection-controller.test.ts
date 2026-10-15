import { describe, expect, it, vi } from "vitest";
import type { SshServerProfile } from "../profiles/profile";
import type { AppStateStatusLike } from "../realtime/app-state";
import { createSshConnectionController } from "./connection-controller";
import type {
  SshHostKeyEvent,
  SshOpenOptions,
  SshTransport,
} from "./transport";

const profile: SshServerProfile = {
  id: "a",
  label: "SSH",
  createdAt: 0,
  mode: "ssh",
  serverUrl: "ssh://host:22",
  hostname: "host",
  port: 22,
  username: "user",
  keyRef: "key",
  keyEncrypted: true,
  hostKey: null,
  localHost: "127.64.0.1",
  remoteHost: "127.0.0.1",
  remotePort: 38886,
};

function setup() {
  const pending: Array<{
    attemptId: string;
    resolve: (result: {
      tunnelId: string;
      serverUrl: string;
      tunnelSecret: string;
    }) => void;
    reject: (error: Error) => void;
  }> = [];
  let closed: (event: {
    attemptId: string;
    detail?: string;
    code?: string;
  }) => void = () => {};
  let hostKey: (event: SshHostKeyEvent) => void = () => {};
  let appChange: (state: AppStateStatusLike) => void = () => {};
  const transport: SshTransport = {
    open: vi.fn(
      (options: SshOpenOptions) =>
        new Promise<{
          tunnelId: string;
          serverUrl: string;
          tunnelSecret: string;
        }>((resolve, reject) => {
          pending.push({ attemptId: options.attemptId, resolve, reject });
        }),
    ),
    cancel: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
    confirmHostKey: vi.fn(async () => {}),
    onState: () => () => {},
    onClosed(listener) {
      closed = listener;
      return () => {};
    },
    onHostKey(listener) {
      hostKey = listener;
      return () => {};
    },
  };
  const controller = createSshConnectionController({
    transport,
    appState: {
      currentState: "active",
      addEventListener(_type, listener) {
        appChange = listener;
        return { remove() {} };
      },
    },
  });
  return {
    controller,
    transport,
    pending,
    closed: (attemptId: string, code?: string) => closed({ attemptId, code }),
    emitHostKey: (event: SshHostKeyEvent) => hostKey(event),
    appChange: (state: AppStateStatusLike) => appChange(state),
  };
}

const flush = async () => {
  await Promise.resolve();
  await Promise.resolve();
};

describe("SSH connection lifecycle", () => {
  it("disposes stale successes across A-B-A without accepting the original A", async () => {
    const s = setup();
    s.controller.activate(profile);
    s.controller.providePassphrase("");
    s.controller.activate({ ...profile, id: "b" });
    s.controller.providePassphrase("");
    s.controller.activate(profile);
    s.controller.providePassphrase("");
    expect(new Set(s.pending.map((p) => p.attemptId)).size).toBe(3);
    s.pending[0]!.resolve({
      tunnelId: "stale",
      serverUrl: "http://127.64.0.1:38886",
      tunnelSecret: "secret",
    });
    await flush();
    expect(s.transport.close).toHaveBeenCalledWith({ tunnelId: "stale" });
    expect(s.controller.getState()?.status).toBe("connecting");
    s.pending[2]!.resolve({
      tunnelId: "latest",
      serverUrl: "http://127.64.0.1:38886",
      tunnelSecret: "secret",
    });
    await flush();
    expect(s.controller.getState()?.status).toBe("ready");
    s.controller.dispose();
  });

  it("closes a live tunnel on background and reopens on active", async () => {
    const s = setup();
    s.controller.activate(profile);
    s.controller.providePassphrase("");
    s.pending[0]!.resolve({
      tunnelId: "live",
      serverUrl: "http://127.64.0.1:38886",
      tunnelSecret: "secret",
    });
    await flush();
    s.appChange("background");
    expect(s.transport.close).toHaveBeenCalledWith({ tunnelId: "live" });
    expect(s.controller.getState()?.status).toBe("suspended");
    s.appChange("active");
    expect(s.pending).toHaveLength(2);
    s.controller.dispose();
  });

  it("blocks changed host keys without retrying or permitting confirmation", () => {
    const s = setup();
    s.controller.activate({ ...profile, hostKey: "trusted" });
    s.controller.providePassphrase("");
    s.emitHostKey({
      attemptId: s.pending[0]!.attemptId,
      hostKey: "different",
      fingerprint: "SHA256:key",
      changed: true,
    });
    expect(s.controller.getState()?.status).toBe("error");
    s.controller.confirmHostKey(true);
    expect(s.transport.confirmHostKey).not.toHaveBeenCalled();
    s.appChange("background");
    s.appChange("active");
    expect(s.pending).toHaveLength(1);
    s.controller.dispose();
  });
});

it("bounds dropped-tunnel reconnects and cancels scheduled retries on deactivation", async () => {
  vi.useFakeTimers();
  const s = setup();
  try {
    s.controller.activate(profile);
    s.controller.providePassphrase("");
    for (let index = 0; index < 4; index++) {
      s.pending[index]!.resolve({
        tunnelId: `tunnel-${index}`,
        serverUrl: "http://127.64.0.1:38886",
        tunnelSecret: "secret",
      });
      await flush();
      s.closed(s.pending[index]!.attemptId);
      await vi.advanceTimersByTimeAsync(8000);
    }
    expect(s.pending).toHaveLength(4);
    expect(s.controller.getState()?.status).toBe("error");
    s.controller.retry();
    s.controller.providePassphrase("");
    s.pending[4]!.resolve({
      tunnelId: "next",
      serverUrl: "http://127.64.0.1:38886",
      tunnelSecret: "secret",
    });
    await flush();
    s.closed(s.pending[4]!.attemptId);
    s.controller.activate(null);
    await vi.advanceTimersByTimeAsync(8000);
    expect(s.pending).toHaveLength(5);
  } finally {
    s.controller.dispose();
    vi.useRealTimers();
  }
});

it("retries network failures during recovery and cancels a queued recovery on background", async () => {
  vi.useFakeTimers();
  const s = setup();
  try {
    s.controller.activate(profile);
    s.controller.providePassphrase("");
    s.pending[0]!.resolve({
      tunnelId: "live",
      serverUrl: "http://127.64.0.1:38886",
      tunnelSecret: "secret",
    });
    await flush();
    s.closed(s.pending[0]!.attemptId);
    await vi.advanceTimersByTimeAsync(1000);
    s.pending[1]!.reject(new Error("Network unavailable"));
    await flush();
    await vi.advanceTimersByTimeAsync(2000);
    expect(s.pending).toHaveLength(3);
    s.pending[2]!.reject(new Error("Connection timed out"));
    await flush();
    s.appChange("background");
    await vi.advanceTimersByTimeAsync(10000);
    expect(s.pending).toHaveLength(3);
  } finally {
    s.controller.dispose();
    vi.useRealTimers();
  }
});

it("does not retry authentication failure while recovering a dropped tunnel", async () => {
  vi.useFakeTimers();
  const s = setup();
  try {
    s.controller.activate(profile);
    s.controller.providePassphrase("");
    s.pending[0]!.resolve({
      tunnelId: "live",
      serverUrl: "http://127.64.0.1:38886",
      tunnelSecret: "secret",
    });
    await flush();
    s.closed(s.pending[0]!.attemptId);
    await vi.advanceTimersByTimeAsync(1000);
    s.pending[1]!.reject(
      Object.assign(new Error("Public key authentication failed"), {
        code: "SSH_AUTH_FAILED",
      }),
    );
    await flush();
    await vi.advanceTimersByTimeAsync(10000);
    expect(s.pending).toHaveLength(2);
  } finally {
    s.controller.dispose();
    vi.useRealTimers();
  }
});

it("continues recovery when a native close precedes its rejected open promise", async () => {
  vi.useFakeTimers();
  const s = setup();
  try {
    s.controller.activate(profile);
    s.controller.providePassphrase("");
    s.pending[0]!.resolve({
      tunnelId: "live",
      serverUrl: "http://127.64.0.1:38886",
      tunnelSecret: "secret",
    });
    await flush();
    s.closed(s.pending[0]!.attemptId);
    await vi.advanceTimersByTimeAsync(1000);
    s.closed(s.pending[1]!.attemptId, "SSH_TIMEOUT");
    s.pending[1]!.reject(new Error("Connection timed out"));
    await flush();
    await vi.advanceTimersByTimeAsync(2000);
    expect(s.pending).toHaveLength(3);
    s.closed(s.pending[2]!.attemptId, "SSH_AUTH_FAILED");
    s.pending[2]!.reject(new Error("Authentication failed"));
    await flush();
    await vi.advanceTimersByTimeAsync(10000);
    expect(s.pending).toHaveLength(3);
  } finally {
    s.controller.dispose();
    vi.useRealTimers();
  }
});

function rejectOpen(entry: { reject: (error: Error) => void }, code?: string) {
  entry.reject(Object.assign(new Error("failure"), code ? { code } : {}));
}

describe("SSH retry policy", () => {
  it("backs off 1, 2 and 4 seconds and stops after three retries", async () => {
    vi.useFakeTimers();
    const s = setup();
    try {
      s.controller.activate(profile);
      s.controller.providePassphrase("");
      s.pending[0]!.resolve({
        tunnelId: "live",
        serverUrl: "http://127.64.0.1:38886",
        tunnelSecret: "secret",
      });
      await flush();
      s.closed(s.pending[0]!.attemptId);
      await vi.advanceTimersByTimeAsync(999);
      expect(s.pending).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(s.pending).toHaveLength(2);
      rejectOpen(s.pending[1]!, "SSH_OPEN_FAILED");
      await flush();
      await vi.advanceTimersByTimeAsync(1999);
      expect(s.pending).toHaveLength(2);
      await vi.advanceTimersByTimeAsync(1);
      expect(s.pending).toHaveLength(3);
      rejectOpen(s.pending[2]!, "SSH_TIMEOUT");
      await flush();
      await vi.advanceTimersByTimeAsync(3999);
      expect(s.pending).toHaveLength(3);
      await vi.advanceTimersByTimeAsync(1);
      expect(s.pending).toHaveLength(4);
      rejectOpen(s.pending[3]!, "SSH_OPEN_FAILED");
      await flush();
      await vi.advanceTimersByTimeAsync(60000);
      expect(s.pending).toHaveLength(4);
      expect(s.controller.getState()?.status).toBe("error");
    } finally {
      s.controller.dispose();
      vi.useRealTimers();
    }
  });

  it.each(["SSH_AUTH_FAILED", "SSH_HOST_KEY_CHANGED", "SSH_HOST_KEY_REJECTED"])(
    "does not reconnect an established tunnel closed with %s",
    async (code) => {
      vi.useFakeTimers();
      const s = setup();
      try {
        s.controller.activate(profile);
        s.controller.providePassphrase("");
        s.pending[0]!.resolve({
          tunnelId: "live",
          serverUrl: "http://127.64.0.1:38886",
          tunnelSecret: "secret",
        });
        await flush();
        s.closed(s.pending[0]!.attemptId, code);
        await vi.advanceTimersByTimeAsync(10000);
        expect(s.pending).toHaveLength(1);
        expect(s.controller.getState()?.status).toBe("error");
      } finally {
        s.controller.dispose();
        vi.useRealTimers();
      }
    },
  );

  it("treats an unknown close code as an open failure", async () => {
    vi.useFakeTimers();
    const s = setup();
    try {
      s.controller.activate(profile);
      s.controller.providePassphrase("");
      s.pending[0]!.resolve({
        tunnelId: "live",
        serverUrl: "http://127.64.0.1:38886",
        tunnelSecret: "secret",
      });
      await flush();
      s.closed(s.pending[0]!.attemptId, "SOMETHING_NEW");
      await vi.advanceTimersByTimeAsync(1000);
      expect(s.pending).toHaveLength(2);
    } finally {
      s.controller.dispose();
      vi.useRealTimers();
    }
  });

  it("does not schedule a reconnect when the user deactivates mid-attempt", async () => {
    vi.useFakeTimers();
    const s = setup();
    try {
      s.controller.activate(profile);
      s.controller.providePassphrase("");
      s.pending[0]!.resolve({
        tunnelId: "live",
        serverUrl: "http://127.64.0.1:38886",
        tunnelSecret: "secret",
      });
      await flush();
      s.closed(s.pending[0]!.attemptId);
      await vi.advanceTimersByTimeAsync(1000);
      s.controller.activate(null);
      rejectOpen(s.pending[1]!, "SSH_OPEN_FAILED");
      await flush();
      await vi.advanceTimersByTimeAsync(10000);
      expect(s.pending).toHaveLength(2);
    } finally {
      s.controller.dispose();
      vi.useRealTimers();
    }
  });
});

describe("unencrypted keys", () => {
  it("connects without a passphrase prompt and does not prompt after auth failure", async () => {
    const s = setup();
    s.controller.activate({ ...profile, keyEncrypted: false });
    expect(s.controller.getState()?.status).toBe("connecting");
    expect(s.transport.open).toHaveBeenCalledWith(
      expect.objectContaining({ passphrase: null }),
    );
    rejectOpen(s.pending[0]!, "SSH_AUTH_FAILED");
    await flush();
    expect(s.controller.getState()?.status).toBe("error");
    s.controller.retry();
    expect(s.controller.getState()?.status).toBe("connecting");
    expect(s.pending).toHaveLength(2);
    s.controller.dispose();
  });

  it("still prompts for encrypted keys", () => {
    const s = setup();
    s.controller.activate(profile);
    expect(s.controller.getState()?.status).toBe("passphrase-needed");
    expect(s.pending).toHaveLength(0);
    s.controller.dispose();
  });
});
