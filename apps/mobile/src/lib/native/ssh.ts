import { Platform } from "react-native";
import nativeModule from "../../../modules/bb-ssh";
import type { SshTransport } from "../ssh/transport";
import { sshLoopbackAddress } from "../profiles/ssh-profile";
import { expoSecureStorage } from "./expo-secure-storage";
import { probeServer } from "../profiles/probe";

const ADDRESS_KEY = "bb.ssh.address-sequence";
let allocationChain: Promise<unknown> = Promise.resolve();

export function isSshAvailable(): boolean {
  return Platform.OS === "android" && nativeModule !== null;
}

function requireSsh() {
  if (!isSshAvailable() || !nativeModule) {
    throw new Error("SSH requires an Android build with the bb SSH module");
  }
  return nativeModule;
}

export function importSshKey(privateKey: string): Promise<string> {
  return requireSsh().importKey(privateKey);
}

export function deleteSshKey(keyRef: string): Promise<void> {
  return requireSsh().deleteKey(keyRef);
}

export function allocateSshLocalHost(): Promise<string> {
  const operation = allocationChain.then(async () => {
    const raw = await expoSecureStorage.getItem(ADDRESS_KEY);
    const previous = raw === null ? 0 : Number(raw);
    if (!Number.isInteger(previous) || previous < 0) {
      throw new Error("Saved SSH address allocation is invalid");
    }
    const next = previous + 1;
    const address = sshLoopbackAddress(next);
    await expoSecureStorage.setItem(ADDRESS_KEY, String(next));
    return address;
  });
  allocationChain = operation.catch(() => undefined);
  return operation;
}

export function createNativeSshTransport(): SshTransport | undefined {
  if (!isSshAvailable()) return undefined;
  const module = requireSsh();
  const probes = new Map<string, AbortController>();
  return {
    async open(options) {
      const abort = new AbortController();
      probes.set(options.attemptId, abort);
      let tunnelId: string | null = null;
      try {
        const result = await module.open(options);
        tunnelId = result.tunnelId;
        if (abort.signal.aborted) throw new Error("SSH connection cancelled");
        const probe = await probeServer(result.serverUrl, async (url, init) => {
          const combined = new AbortController();
          const cancel = () => combined.abort();
          abort.signal.addEventListener("abort", cancel, { once: true });
          init.signal?.addEventListener("abort", cancel, { once: true });
          if (abort.signal.aborted || init.signal?.aborted) cancel();
          try {
            return await fetch(url, { ...init, signal: combined.signal });
          } finally {
            abort.signal.removeEventListener("abort", cancel);
            init.signal?.removeEventListener("abort", cancel);
          }
        });
        if (abort.signal.aborted) throw new Error("SSH connection cancelled");
        if (!probe.ok)
          throw new Error(
            `SSH connected, but bb is unavailable: ${probe.error}`,
          );
        return result;
      } catch (error) {
        if (tunnelId) await module.close(tunnelId);
        throw error;
      } finally {
        probes.delete(options.attemptId);
      }
    },
    confirmHostKey: ({ attemptId, accept }) =>
      module.confirmHostKey(attemptId, accept),
    cancel({ attemptId }) {
      probes.get(attemptId)?.abort();
      return module.cancel(attemptId);
    },
    close: ({ tunnelId }) => module.close(tunnelId),
    onState(listener) {
      const subscription = module.addListener("onState", listener);
      return () => subscription.remove();
    },
    onHostKey(listener) {
      const subscription = module.addListener("onHostKey", (event) =>
        listener(event),
      );
      return () => subscription.remove();
    },
    onClosed(listener) {
      const subscription = module.addListener("onClosed", (event) =>
        listener({
          attemptId: event.attemptId,
          detail: event.message,
          code: event.code,
        }),
      );
      return () => subscription.remove();
    },
  };
}
