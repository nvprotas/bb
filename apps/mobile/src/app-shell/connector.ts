import {
  createActiveProfileConnector,
  type ActiveProfileConnector,
} from "@/lib/connection";
import {
  nativeAppState,
  nativeCookieStore,
  nativeSessionCache,
} from "@/lib/native";
import { createNativeSshTransport } from "@/lib/native/ssh";
import { getProfileStore } from "@/lib/native";
import { getAppProfileClientRegistry } from "./client-registry";
import { createSessionScheduler } from "@/lib/session";

let instance: ActiveProfileConnector | null = null;

export function getActiveProfileConnector(): ActiveProfileConnector {
  if (!instance) {
    instance = createActiveProfileConnector({
      registry: getAppProfileClientRegistry(),
      appState: nativeAppState,
      sshTransport: createNativeSshTransport(),
      onHostKeyTrusted: async (profile, hostKey) => {
        await getProfileStore().updateProfile(profile.id, { hostKey });
      },
      createSessionScheduler: () =>
        createSessionScheduler({
          cookieStore: nativeCookieStore,
          sessionCache: nativeSessionCache,
        }),
    });
  }
  return instance;
}

export function waitForActiveConnection(profileId: string): Promise<boolean> {
  const profile = getProfileStore()
    .listProfiles()
    .find((saved) => saved.id === profileId);
  const timeoutMs = profile?.mode === "ssh" ? 120_000 : 5_000;
  const connector = getActiveProfileConnector();
  if (connector.getSnapshot()?.profile.id === profileId) {
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      unsubscribe();
      resolve(ok);
    };
    const unsubscribe = connector.subscribe(() => {
      if (connector.getSnapshot()?.profile.id === profileId) finish(true);
      if (connector.getSshState()?.status === "error") finish(false);
    });
    const timer = setTimeout(() => finish(false), timeoutMs);
  });
}
