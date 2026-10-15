import * as Notifications from "expo-notifications";
import { getThreadRoutePath } from "@bb/client-core";
import { useRouter } from "expo-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AppState, type AppStateStatus } from "react-native";
import {
  useAppRevealed,
  useProfiles,
  useRealtimeConnectionState,
} from "@/app-shell";
import {
  parsePushNotificationData,
  resolvePushTargetProfile,
  isPushRegistrationAllowed,
  shouldOfferPushPrompt,
  type PushNotificationTarget,
  type PushSyncProfile,
} from "@/data/notifications";
import { ActionSheet, toast, useSheet } from "@/ui";
import { webViewShellHref } from "@/screens/shell/hrefs";
import { AppBadgeSync } from "./AppBadgeSync";
import { getPushNotificationsModule } from "./expo-push-module";
import { getPushRegistrationController } from "./push-controller";
import { getPushStore } from "./push-storage";
import { hasThreadOnServer } from "./thread-probe";
import { usePushStoreSnapshot } from "./use-push-store";

export function PushNotificationsHost() {
  const { status, profiles, activeProfile, connection } = useProfiles();
  const syncProfile = useMemo(
    () =>
      activeProfile?.mode === "ssh" &&
      connection?.profile.id === activeProfile.id
        ? { ...activeProfile, serverUrl: connection.client.serverUrl }
        : activeProfile,
    [activeProfile, connection],
  );
  const syncProfiles = profiles.map((profile) =>
    syncProfile && profile.id === syncProfile.id ? syncProfile : profile,
  );
  const syncProfilesRef = useRef(syncProfiles);
  useEffect(() => {
    syncProfilesRef.current = syncProfiles;
  }, [syncProfiles]);
  const realtimeState = useRealtimeConnectionState();
  const connected = connection !== null && realtimeState === "connected";
  const controller = getPushRegistrationController();
  const notifications = getPushNotificationsModule();
  const storeSnapshot = usePushStoreSnapshot();
  const router = useRouter();
  const profilesRef = useRef(profiles);
  const activeProfileIdRef = useRef(activeProfile?.id ?? null);
  useEffect(() => {
    profilesRef.current = profiles;
    activeProfileIdRef.current = activeProfile?.id ?? null;
  }, [profiles, activeProfile]);

  const activeEnabled =
    activeProfile !== null &&
    storeSnapshot.enabledProfileIds.includes(activeProfile.id);

  useEffect(() => {
    Notifications.setNotificationHandler({
      handleNotification: async () => ({
        shouldShowBanner: false,
        shouldShowList: true,
        shouldPlaySound: false,
        shouldSetBadge: false,
      }),
    });
    return () => Notifications.setNotificationHandler(null);
  }, []);

  const openTarget = useCallback(
    async (target: PushNotificationTarget) => {
      const profile = await resolvePushTargetProfile(target, {
        profiles: profilesRef.current,
        activeProfileId: activeProfileIdRef.current,
        registrations: getPushStore().getSnapshot().registrations,
        hasThread: hasThreadOnServer,
      });
      if (!profile) {
        toast.error("Could not open the thread", {
          description:
            "The notification could not be matched to a saved server. Open the server and select the thread.",
        });
        return;
      }
      router.push(
        webViewShellHref({
          profileId: profile.id,
          path:
            target.projectId === null
              ? `/threads/${target.threadId}`
              : getThreadRoutePath({
                  projectId: target.projectId,
                  threadId: target.threadId,
                }),
        }),
      );
    },
    [router],
  );

  useEffect(() => {
    const handle = (response: Notifications.NotificationResponse) => {
      const target = parsePushNotificationData(
        response.notification.request.content.data,
      );
      if (target) void openTarget(target);
    };
    const subscription =
      Notifications.addNotificationResponseReceivedListener(handle);
    const last = Notifications.getLastNotificationResponse();
    if (last) {
      Notifications.clearLastNotificationResponse();
      handle(last);
    }
    return () => subscription.remove();
  }, [openTarget]);

  useEffect(() => {
    if (!syncProfile || !connected) return;
    void controller.sync(syncProfile);
  }, [controller, syncProfile, connected, activeEnabled]);

  useEffect(() => {
    const onChange = (state: AppStateStatus) => {
      if (state !== "active") return;
      void controller.refreshPermission().then(() => {
        if (syncProfile) void controller.sync(syncProfile);
      });
    };
    const subscription = AppState.addEventListener("change", onChange);
    return () => subscription.remove();
  }, [controller, syncProfile]);

  useEffect(
    () =>
      notifications.addTokenListener((deviceToken) => {
        void controller.handleTokenRolled(syncProfilesRef.current, deviceToken);
      }),
    [controller, notifications],
  );

  useEffect(() => {
    if (status !== "ready") return;
    void controller
      .reconcileRemovedProfiles(profiles.map((p) => p.id))
      .catch((error) => {
        console.warn("Could not clean up push registrations", error);
      });
  }, [controller, status, profiles]);

  return (
    <>
      {connection ? <AppBadgeSync /> : null}
      <FirstRunPrompt
        profile={syncProfile}
        connected={connected}
        available={
          notifications.projectId !== null &&
          (activeProfile === null || isPushRegistrationAllowed(syncProfile!))
        }
        prompted={storeSnapshot.prompted}
        enabled={activeEnabled}
      />
    </>
  );
}

function FirstRunPrompt({
  profile,
  connected,
  available,
  prompted,
  enabled,
}: {
  profile: PushSyncProfile | null;
  connected: boolean;
  available: boolean;
  prompted: boolean;
  enabled: boolean;
}) {
  const sheet = useSheet();
  const controller = getPushRegistrationController();
  const store = getPushStore();
  const notifications = getPushNotificationsModule();
  const [presentedFor, setPresentedFor] = useState<string | null>(null);
  const revealed = useAppRevealed();
  const shouldAsk =
    revealed &&
    available &&
    !prompted &&
    connected &&
    profile !== null &&
    presentedFor === null;

  useEffect(() => {
    if (!shouldAsk || !profile) return;
    let cancelled = false;
    void notifications.getPermission().then((permission) => {
      if (cancelled || !shouldOfferPushPrompt({ permission, enabled })) {
        return;
      }
      setPresentedFor(profile.id);
      sheet.present();
    });
    return () => {
      cancelled = true;
    };
  }, [shouldAsk, profile, enabled, notifications, sheet]);

  return (
    <ActionSheet
      presentation="prompt"
      controller={sheet}
      title="Get notified when a thread needs you?"
      cancelLabel={process.env.EXPO_OS === "ios" ? "Cancel" : null}
      message="bb can send a push notification when a thread finishes, hits an error, or is waiting for your input. You can change this per server in Settings."
      actions={[
        {
          key: "enable",
          label: "Turn on notifications",
          icon: "Bell",
          onPress: () => {
            if (!profile) return;
            void controller.setEnabled(profile, true).then((outcome) => {
              if (outcome.action === "failed") {
                toast.error("Could not turn on notifications", {
                  description: outcome.error,
                });
              }
            });
          },
        },
        {
          key: "later",
          label: "Not now",
          onPress: () => store.markPrompted(),
        },
      ]}
      onDismiss={() => {
        if (!store.hasPrompted()) store.markPrompted();
      }}
    />
  );
}
