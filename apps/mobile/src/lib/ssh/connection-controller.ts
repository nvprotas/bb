import type { SshServerProfile } from "../profiles/profile";
import type { AppStateLike } from "../realtime/app-state";
import {
  isRetryableSshErrorCode,
  parseSshErrorCode,
  type SshConnectionState,
  type SshTransport,
} from "./transport";

let attemptSequence = 0;

export function createSshConnectionController(deps: {
  transport: SshTransport;
  appState: AppStateLike;
  onHostKeyTrusted?: (
    profile: SshServerProfile,
    hostKey: string,
  ) => void | Promise<void>;
}) {
  let profile: SshServerProfile | null = null;
  let state: SshConnectionState | null = null;
  let attemptId: string | null = null;
  let foreground = deps.appState.currentState === "active";
  let attempt: { trustSaved: Promise<void> } | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let reconnectCount = 0;
  let recovering = false;
  let passphrase: string | null = null;
  const listeners = new Set<() => void>();
  const publish = (next: SshConnectionState | null) => {
    state = next;
    for (const listener of listeners) listener();
  };
  const ignoreFailure = (operation: Promise<void>) => {
    void operation.catch(() => {});
  };
  const stop = () => {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    const previous = attemptId;
    attemptId = null;
    if (previous) ignoreFailure(deps.transport.cancel({ attemptId: previous }));
    if (state?.status === "ready")
      ignoreFailure(deps.transport.close({ tunnelId: state.tunnelId }));
  };
  const fail = (detail: string) => {
    stop();
    publish({ status: "error", detail });
  };
  const scheduleReconnect = () => {
    if (!recovering || !foreground || !profile || reconnectCount >= 3) return;
    const delay = 1000 * 2 ** reconnectCount++;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      start();
    }, delay);
  };
  const start = () => {
    stop();
    if (!profile) {
      publish(null);
      return;
    }
    if (!foreground) {
      publish({ status: "suspended" });
      return;
    }
    if (profile.keyEncrypted && passphrase === null) {
      publish({
        status: "passphrase-needed",
        detail: "Enter the private key passphrase",
      });
      return;
    }
    const keyPassphrase = profile.keyEncrypted ? passphrase : null;
    const current = { trustSaved: Promise.resolve() };
    attempt = current;
    const currentAttempt = `ssh-${++attemptSequence}`;
    attemptId = currentAttempt;
    publish({ status: "connecting" });
    void deps.transport
      .open({
        ...profile,
        attemptId: currentAttempt,
        passphrase: keyPassphrase,
      })
      .then(async (result) => {
        try {
          await current.trustSaved;
        } catch {
          ignoreFailure(deps.transport.close({ tunnelId: result.tunnelId }));
          return;
        }
        if (attemptId !== currentAttempt) {
          ignoreFailure(deps.transport.close({ tunnelId: result.tunnelId }));
          return;
        }
        let url: URL;
        try {
          url = new URL(result.serverUrl);
        } catch {
          ignoreFailure(deps.transport.close({ tunnelId: result.tunnelId }));
          fail("Invalid SSH tunnel address");
          return;
        }
        if (
          url.protocol !== "http:" ||
          url.hostname !== profile?.localHost ||
          url.username ||
          url.password
        ) {
          ignoreFailure(deps.transport.close({ tunnelId: result.tunnelId }));
          fail("Invalid SSH tunnel address");
          return;
        }
        publish({ status: "ready", ...result });
      })
      .catch((error: unknown) => {
        if (attemptId !== currentAttempt) return;
        const detail =
          error instanceof Error ? error.message : "SSH connection failed";
        const code = parseSshErrorCode(
          typeof error === "object" && error !== null && "code" in error
            ? error.code
            : undefined,
        );
        fail(detail);
        if (isRetryableSshErrorCode(code)) scheduleReconnect();
      });
  };
  const unsubscribeState = deps.transport.onState((event) => {
    if (event.attemptId !== attemptId) return;
    if (event.state === "passphrase-needed") {
      stop();
      publish({
        status: "passphrase-needed",
        detail: event.detail ?? "Enter the private key passphrase",
      });
    } else if (event.state === "error") {
      const detail = event.detail ?? "SSH connection failed";
      fail(detail);
    }
  });
  const unsubscribeHostKey = deps.transport.onHostKey((event) => {
    if (event.attemptId !== attemptId) return;
    if (
      event.changed ||
      (profile?.hostKey !== null && profile?.hostKey !== event.hostKey)
    ) {
      fail(
        "SSH host key has changed. Verify the server identity before replacing this profile.",
      );
      return;
    }
    publish({
      status: "host-key-confirmation",
      hostKey: event.hostKey,
      fingerprint: event.fingerprint,
      changed: false,
    });
  });
  const unsubscribeClosed = deps.transport.onClosed((event) => {
    if (event.attemptId !== attemptId) return;
    const established = state?.status === "ready";
    const detail = event.detail ?? "SSH connection closed";
    const networkFailure = isRetryableSshErrorCode(
      parseSshErrorCode(event.code),
    );
    fail(detail);
    if (networkFailure && (established || recovering)) {
      if (established) recovering = true;
      scheduleReconnect();
    }
  });
  const appSubscription = deps.appState.addEventListener("change", (next) => {
    if (next === "active") {
      if (foreground) return;
      foreground = true;
      if (profile && state?.status === "suspended") start();
    } else if (next === "background") {
      foreground = false;
      const terminalError =
        state?.status === "error" && reconnectTimer === null;
      stop();
      if (profile && !terminalError) publish({ status: "suspended" });
    }
  });
  return {
    activate(next: SshServerProfile | null) {
      profile = next;
      passphrase = null;
      reconnectCount = 0;
      recovering = false;
      start();
    },
    updateProfile(next: SshServerProfile) {
      profile = next;
    },
    getState: () => state,
    subscribe(listener: () => void) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    confirmHostKey(accept: boolean) {
      if (
        state?.status !== "host-key-confirmation" ||
        !attemptId ||
        !profile ||
        !attempt
      )
        return;
      const currentAttempt = attemptId;
      const hostKey = state.hostKey;
      if (!accept) {
        ignoreFailure(
          deps.transport.confirmHostKey({
            attemptId: currentAttempt,
            accept: false,
          }),
        );
        fail("SSH host key was rejected");
        return;
      }
      profile = { ...profile, hostKey };
      const trustedProfile = profile;
      publish({ status: "connecting" });
      attempt.trustSaved = Promise.resolve().then(() =>
        deps.onHostKeyTrusted?.(trustedProfile, hostKey),
      );
      void attempt.trustSaved
        .then(() => {
          if (attemptId === currentAttempt)
            return deps.transport.confirmHostKey({
              attemptId: currentAttempt,
              accept: true,
            });
        })
        .catch((error: unknown) => {
          if (attemptId === currentAttempt)
            fail(
              error instanceof Error
                ? error.message
                : "Could not trust SSH host key",
            );
        });
    },
    providePassphrase(value: string) {
      if (state?.status === "passphrase-needed") {
        passphrase = value;
        start();
      }
    },
    retry() {
      passphrase = null;
      reconnectCount = 0;
      recovering = false;
      start();
    },
    dispose() {
      stop();
      unsubscribeState();
      unsubscribeHostKey();
      unsubscribeClosed();
      appSubscription.remove();
      listeners.clear();
    },
  };
}
