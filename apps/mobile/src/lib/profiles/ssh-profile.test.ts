import { describe, expect, it } from "vitest";
import { createProfileStore } from "./profile-store";
import { createMemorySecureStorage } from "./secure-storage";
import { sshLoopbackAddress, sshServerUrl } from "./ssh-profile";

describe("saved SSH hosts", () => {
  it("keeps distinct host identities and trusted keys across reload and switching", async () => {
    const storage = createMemorySecureStorage();
    let sequence = 0;
    const store = createProfileStore({
      storage,
      generateId: () => `host-${++sequence}`,
    });
    const firstInput = {
      mode: "ssh",
      label: "First",
      serverUrl: sshServerUrl("first.example", 22),
      hostname: "first.example",
      port: 22,
      username: "dev",
      keyRef: "key-a",
      hostKey: null,
      localHost: sshLoopbackAddress(1),
      remoteHost: "127.0.0.1",
      remotePort: 38886,
    } as const;
    const first = await store.addProfile(firstInput);
    const second = await store.addProfile({
      ...firstInput,
      hostname: "second.example",
      serverUrl: sshServerUrl("second.example", 2222),
      port: 2222,
      label: "Second",
      keyRef: "key-b",
      localHost: sshLoopbackAddress(2),
    });
    await store.updateProfile(first.id, {
      hostKey: "ssh-ed25519 trusted-first-key",
    });
    await store.setActiveProfile(second.id);
    await store.setActiveProfile(first.id);
    const restored = createProfileStore({ storage });
    await restored.load();
    expect(restored.getSnapshot().activeProfileId).toBe(first.id);
    expect(restored.listProfiles()).toHaveLength(2);
    expect(restored.listProfiles()[0]).toMatchObject({
      hostKey: "ssh-ed25519 trusted-first-key",
      localHost: "127.64.0.1",
    });
    expect(restored.listProfiles()[1]).toMatchObject({
      hostKey: null,
      localHost: "127.64.0.2",
      port: 2222,
    });
    await expect(
      restored.updateProfile(first.id, { serverUrl: "http://another-host" }),
    ).rejects.toThrow("not editable");
  });

  it("rejects wildcard addresses and keeps allocation within private loopback hosts", async () => {
    expect(sshLoopbackAddress(65536)).toBe("127.65.0.0");
    expect(() => sshLoopbackAddress(0)).toThrow();
    expect(() => sshLoopbackAddress(64 * 65536)).toThrow();
    const store = createProfileStore({
      storage: createMemorySecureStorage(),
      generateId: () => "bad",
    });
    await expect(
      store.addProfile({
        mode: "ssh",
        label: "Invalid",
        serverUrl: "ssh://server:22",
        hostname: "server",
        port: 22,
        username: "user",
        keyRef: "key",
        hostKey: null,
        localHost: "0.0.0.0",
        remoteHost: "127.0.0.1",
        remotePort: 38886,
      }),
    ).rejects.toThrow();
  });
});
