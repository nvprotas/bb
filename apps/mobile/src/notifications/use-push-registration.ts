import { useProfiles } from "@/app-shell";
import { useCallback, useEffect, useMemo, useSyncExternalStore } from "react";
import {
  describePushStatus,
  isPushRegistrationAllowed,
  type PushPermissionState,
  type PushProfileSyncState,
  type PushSyncOutcome,
} from "@/data/notifications";
import { getPushNotificationsModule } from "./expo-push-module";
import { getPushRegistrationController } from "./push-controller";
import { usePushStoreSnapshot } from "./use-push-store";

export interface PushRegistration {
  available: boolean;
  enabled: boolean;
  permission: PushPermissionState | null;
  syncing: boolean;
  statusText: string;
  setEnabled(enabled: boolean): Promise<PushSyncOutcome>;
}

const IDLE_STATE: PushProfileSyncState = {
  syncing: false,
  lastOutcome: null,
  permission: null,
};

export function usePushRegistration(profile: {
  id: string;
  serverUrl: string;
  mode: "direct" | "connect" | "ssh";
}): PushRegistration {
  const { connection } = useProfiles();
  const syncProfile = useMemo(
    () =>
      profile.mode === "ssh" && connection?.profile.id === profile.id
        ? { ...profile, serverUrl: connection.client.serverUrl }
        : profile,
    [profile, connection],
  );
  const controller = getPushRegistrationController();
  const notifications = getPushNotificationsModule();
  const storeSnapshot = usePushStoreSnapshot();
  const controllerSnapshot = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot,
    controller.getSnapshot,
  );
  useEffect(() => {
    void controller.refreshPermission();
  }, [controller]);

  const state = controllerSnapshot.byProfileId[profile.id] ?? IDLE_STATE;
  const enabled = storeSnapshot.enabledProfileIds.includes(profile.id);
  const registration = storeSnapshot.registrations[profile.id] ?? null;
  const setEnabled = useCallback(
    (next: boolean) =>
      syncProfile.mode === "ssh" && !isPushRegistrationAllowed(syncProfile)
        ? Promise.resolve<PushSyncOutcome>({
            action: "skipped",
            reason: "ssh-disconnected",
          })
        : controller.setEnabled(syncProfile, next),
    [controller, syncProfile],
  );
  return {
    available:
      notifications.projectId !== null &&
      isPushRegistrationAllowed(syncProfile),
    enabled,
    permission: state.permission,
    syncing: state.syncing,
    statusText: describePushStatus({
      profile: syncProfile,
      projectId: notifications.projectId,
      enabled,
      permission: state.permission,
      registration,
      lastOutcome: state.lastOutcome,
    }),
    setEnabled,
  };
}
