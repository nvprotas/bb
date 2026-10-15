import { z } from "zod";
import {
  matchProfileForWebLink,
  type LinkProfileLike,
} from "@/lib/links/incoming-link";

export interface PushNotificationTarget {
  subscriptionId?: string;
  threadId: string;
  projectId: string | null;
  serverUrl: string | null;
}

const pushDataSchema = z.object({
  subscriptionId: z.string().min(1).optional(),
  threadId: z.string().min(1),
  projectId: z.string().min(1).nullish(),
  serverUrl: z.string().min(1).nullish(),
  url: z.string().min(1).nullish(),
});

function normalizedHint(value: string, preservePath: boolean): string | null {
  try {
    const url = new URL(value);
    if (!preservePath || url.pathname === "/") return url.origin;
    return `${url.origin}${url.pathname.replace(/\/+$/u, "")}`;
  } catch {
    return null;
  }
}

export function parsePushNotificationData(
  data: unknown,
): PushNotificationTarget | null {
  const parsed = pushDataSchema.safeParse(data);
  if (!parsed.success) return null;
  const serverUrl = parsed.data.serverUrl ?? null;
  const fallbackUrl = parsed.data.url ?? null;
  return {
    ...(parsed.data.subscriptionId
      ? { subscriptionId: parsed.data.subscriptionId }
      : {}),
    threadId: parsed.data.threadId,
    projectId: parsed.data.projectId ?? null,
    serverUrl: serverUrl
      ? normalizedHint(serverUrl, true)
      : fallbackUrl
        ? normalizedHint(fallbackUrl, false)
        : null,
  };
}

export interface ResolvePushTargetProfileDeps {
  profiles: readonly LinkProfileLike[];
  activeProfileId: string | null;
  registrations?: Readonly<Record<string, { subscriptionId: string | null }>>;
  hasThread(serverUrl: string, threadId: string): Promise<boolean>;
}

export async function resolvePushTargetProfile(
  target: PushNotificationTarget,
  deps: ResolvePushTargetProfileDeps,
): Promise<LinkProfileLike | null> {
  if (target.subscriptionId) {
    const matches = deps.profiles.filter(
      (profile) =>
        deps.registrations?.[profile.id]?.subscriptionId ===
        target.subscriptionId,
    );
    if (matches.length === 1) return matches[0]!;
    if (matches.length > 1) return null;
  }
  const profiles = deps.profiles.filter(
    (profile) => !profile.serverUrl.startsWith("ssh://"),
  );
  const hasSshProfiles = profiles.length !== deps.profiles.length;
  if (profiles.length === 0) return null;
  if (target.serverUrl) {
    try {
      const hint = new URL(target.serverUrl);
      if (hasSshProfiles && /^(localhost|127\.|\[::1\])/.test(hint.hostname))
        return null;
      const match = matchProfileForWebLink(
        profiles,
        hint.origin,
        hint.pathname,
      );
      if (match) return match.profile;
    } catch {}
  }
  const ordered = [
    ...profiles.filter((profile) => profile.id === deps.activeProfileId),
    ...profiles.filter((profile) => profile.id !== deps.activeProfileId),
  ];
  for (const profile of ordered) {
    try {
      if (await deps.hasThread(profile.serverUrl, target.threadId)) {
        return profile;
      }
    } catch {}
  }
  return null;
}
