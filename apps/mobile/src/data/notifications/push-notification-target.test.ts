import { describe, expect, it, vi } from "vitest";
import {
  parsePushNotificationData,
  resolvePushTargetProfile,
} from "./push-notification-target";

const sawyer = { id: "p1", serverUrl: "https://sawyer.getbb.app" };
const lan = { id: "p2", serverUrl: "http://192.168.1.20:3000" };

describe("parsePushNotificationData", () => {
  it("reads the thread id and optional project / server hints", () => {
    expect(
      parsePushNotificationData({ threadId: "thr_1", projectId: "prj_1" }),
    ).toEqual({ threadId: "thr_1", projectId: "prj_1", serverUrl: null });
    expect(
      parsePushNotificationData({
        threadId: "thr_1",
        url: "https://sawyer.getbb.app/threads/thr_1",
        extra: 1,
      }),
    ).toEqual({
      threadId: "thr_1",
      projectId: null,
      serverUrl: "https://sawyer.getbb.app",
    });
    expect(
      parsePushNotificationData({
        threadId: "thr_1",
        serverUrl: "https://home.example.com/bb/",
      }),
    ).toEqual({
      threadId: "thr_1",
      projectId: null,
      serverUrl: "https://home.example.com/bb",
    });
  });

  it("rejects payloads without a thread id", () => {
    expect(parsePushNotificationData({ projectId: "p" })).toBeNull();
    expect(parsePushNotificationData("nope")).toBeNull();
    expect(parsePushNotificationData(undefined)).toBeNull();
  });
});

describe("resolvePushTargetProfile", () => {
  const target = { threadId: "thr_1", projectId: null, serverUrl: null };

  it("uses the server hint when it names a saved profile", async () => {
    const hasThread = vi.fn(async () => false);
    expect(
      await resolvePushTargetProfile(
        { ...target, serverUrl: "http://192.168.1.20:3000" },
        { profiles: [sawyer, lan], activeProfileId: "p1", hasThread },
      ),
    ).toBe(lan);
    expect(hasThread).not.toHaveBeenCalled();
  });

  it("matches a server hint with a saved path prefix", async () => {
    const prefixed = {
      id: "p3",
      serverUrl: "https://home.example.com/bb",
    };
    const hasThread = vi.fn(async () => false);
    expect(
      await resolvePushTargetProfile(
        { ...target, serverUrl: "https://home.example.com/bb" },
        { profiles: [sawyer, prefixed], activeProfileId: "p1", hasThread },
      ),
    ).toBe(prefixed);
    expect(hasThread).not.toHaveBeenCalled();
  });

  it("probes the only profile when no server hint matches", async () => {
    const hasThread = vi.fn(async () => true);
    expect(
      await resolvePushTargetProfile(target, {
        profiles: [sawyer],
        activeProfileId: null,
        hasThread,
      }),
    ).toBe(sawyer);
    expect(hasThread).toHaveBeenCalledWith(sawyer.serverUrl, "thr_1");
  });

  it("probes profiles when a server hint does not match", async () => {
    const hasThread = vi.fn(
      async (serverUrl: string) => serverUrl === lan.serverUrl,
    );
    expect(
      await resolvePushTargetProfile(
        { ...target, serverUrl: "https://unknown.example" },
        { profiles: [sawyer, lan], activeProfileId: "p1", hasThread },
      ),
    ).toBe(lan);
    expect(hasThread).toHaveBeenCalledTimes(2);
  });

  it("probes the active profile first, then the others, tolerating failures", async () => {
    const hasThread = vi.fn(async (serverUrl: string) => {
      if (serverUrl === lan.serverUrl) throw new Error("offline");
      return serverUrl === sawyer.serverUrl;
    });
    expect(
      await resolvePushTargetProfile(target, {
        profiles: [sawyer, lan],
        activeProfileId: "p2",
        hasThread,
      }),
    ).toBe(sawyer);
    expect(hasThread.mock.calls.map(([url]) => url)).toEqual([
      lan.serverUrl,
      sawyer.serverUrl,
    ]);
  });

  it("gives up when no server has the thread", async () => {
    expect(
      await resolvePushTargetProfile(target, {
        profiles: [sawyer, lan],
        activeProfileId: "p1",
        hasThread: async () => false,
      }),
    ).toBeNull();
  });
});

describe("SSH push targets", () => {
  it("refuses duplicate subscription IDs and ignores absent registration IDs", async () => {
    const hasThread = vi.fn(async () => true);
    const target = {
      threadId: "thr_1",
      projectId: null,
      serverUrl: null,
      subscriptionId: "duplicate",
    };
    const profiles = [
      { id: "first", serverUrl: "ssh://first:22" },
      { id: "second", serverUrl: "ssh://second:22" },
    ];
    expect(
      await resolvePushTargetProfile(target, {
        profiles,
        activeProfileId: "first",
        hasThread,
        registrations: {
          first: { subscriptionId: "duplicate" },
          second: { subscriptionId: "duplicate" },
        },
      }),
    ).toBeNull();
    expect(
      await resolvePushTargetProfile(target, {
        profiles,
        activeProfileId: "first",
        hasThread,
        registrations: { first: { subscriptionId: null } },
      }),
    ).toBeNull();
    expect(hasThread).not.toHaveBeenCalled();
  });
  const ssh = { id: "ssh-1", serverUrl: "ssh://my-host:22" };
  it("prefers the subscription match over the server hint", async () => {
    const hasThread = vi.fn(async () => true);
    expect(
      await resolvePushTargetProfile(
        {
          threadId: "thr_1",
          projectId: null,
          serverUrl: sawyer.serverUrl,
          subscriptionId: "sub_lan",
        },
        {
          profiles: [sawyer, lan],
          activeProfileId: sawyer.id,
          hasThread,
          registrations: { [lan.id]: { subscriptionId: "sub_lan" } },
        },
      ),
    ).toBe(lan);
    expect(hasThread).not.toHaveBeenCalled();
  });
  it("falls back to hint and probing for direct profiles when no subscription matches", async () => {
    const hasThread = vi.fn(async () => false);
    const base = {
      threadId: "thr_1",
      projectId: null,
      subscriptionId: "sub_unknown",
    };
    const deps = {
      profiles: [sawyer, lan],
      activeProfileId: sawyer.id,
      hasThread,
      registrations: { [sawyer.id]: { subscriptionId: "other" } },
    };
    expect(
      await resolvePushTargetProfile(
        { ...base, serverUrl: lan.serverUrl },
        deps,
      ),
    ).toBe(lan);
    expect(hasThread).not.toHaveBeenCalled();
    const probing = vi.fn(
      async (serverUrl: string) => serverUrl === lan.serverUrl,
    );
    expect(
      await resolvePushTargetProfile(
        { ...base, serverUrl: null },
        { ...deps, hasThread: probing },
      ),
    ).toBe(lan);
  });
  it("never picks an SSH profile when no subscription matches", async () => {
    const hasThread = vi.fn(async () => true);
    const target = {
      threadId: "thr_1",
      projectId: null,
      serverUrl: null,
      subscriptionId: "sub_unknown",
    };
    expect(
      await resolvePushTargetProfile(target, {
        profiles: [ssh],
        activeProfileId: ssh.id,
        hasThread,
        registrations: {},
      }),
    ).toBeNull();
    expect(
      await resolvePushTargetProfile(
        { ...target, serverUrl: "http://127.0.0.1:38886" },
        {
          profiles: [ssh, sawyer],
          activeProfileId: ssh.id,
          hasThread,
          registrations: {},
        },
      ),
    ).toBeNull();
    expect(
      await resolvePushTargetProfile(target, {
        profiles: [ssh, sawyer],
        activeProfileId: ssh.id,
        hasThread,
        registrations: {},
      }),
    ).toBe(sawyer);
    expect(hasThread).toHaveBeenCalledTimes(1);
    expect(hasThread).toHaveBeenCalledWith(sawyer.serverUrl, "thr_1");
  });
  it("routes an inactive SSH profile by its registered subscription without probing", async () => {
    const hasThread = vi.fn(async () => true);
    expect(
      await resolvePushTargetProfile(
        {
          threadId: "thr_1",
          projectId: null,
          serverUrl: "http://127.0.0.1:38886",
          subscriptionId: "sub_ssh",
        },
        {
          profiles: [ssh, sawyer],
          activeProfileId: sawyer.id,
          hasThread,
          registrations: { [ssh.id]: { subscriptionId: "sub_ssh" } },
        },
      ),
    ).toEqual(ssh);
    expect(hasThread).not.toHaveBeenCalled();
  });
  it("does not guess a server from ambiguous loopback hints or fetch logical SSH URLs", async () => {
    const hasThread = vi.fn(async () => true);
    expect(
      await resolvePushTargetProfile(
        {
          threadId: "thr_1",
          projectId: null,
          serverUrl: "http://127.0.0.1:38886",
        },
        { profiles: [ssh, sawyer], activeProfileId: ssh.id, hasThread },
      ),
    ).toBeNull();
    expect(hasThread).not.toHaveBeenCalled();
    expect(
      await resolvePushTargetProfile(
        { threadId: "thr_1", projectId: null, serverUrl: null },
        { profiles: [ssh], activeProfileId: ssh.id, hasThread },
      ),
    ).toBeNull();
    expect(hasThread).not.toHaveBeenCalled();
  });
});
