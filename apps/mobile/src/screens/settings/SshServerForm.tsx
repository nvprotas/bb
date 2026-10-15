import * as DocumentPicker from "expo-document-picker";
import { File } from "expo-file-system";
import { useRouter } from "expo-router";
import { useState } from "react";
import { View } from "react-native";
import { useProfiles } from "@/app-shell";
import { describeError } from "@/lib/describe-error";
import {
  allocateSshLocalHost,
  deleteSshKey,
  importSshKey,
} from "@/lib/native/ssh";
import { PROFILE_LABEL_MAX_LENGTH } from "@/lib/profiles";
import { isSshPrivateKeyEncrypted } from "@/lib/ssh/key-encryption";
import { sshServerUrl } from "@/lib/profiles/ssh-profile";
import { Button, Input, Text, toast } from "@/ui";
import { rawPathHref } from "../shell/hrefs";
import { SettingsSection } from "./SettingsRows";

function parsePort(value: string, name: string): number {
  if (!/^\d+$/.test(value.trim())) throw new Error(`${name} must be a number.`);
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${name} must be between 1 and 65535.`);
  }
  return port;
}

function validateHost(value: string, name: string): string {
  const host = value.trim();
  if (!host || /[\s/@?#\\]/.test(host))
    throw new Error(`Enter a valid ${name}.`);
  const parsed = new URL(
    `http://${host.includes(":") && !host.startsWith("[") ? `[${host}]` : host}`,
  );
  if (parsed.port || parsed.pathname !== "/")
    throw new Error(`Enter ${name} without a port or path.`);
  return host.replace(/^\[|\]$/g, "");
}

export function SshServerForm({
  next,
  onBusyChange,
}: {
  next?: string;
  onBusyChange: (busy: boolean) => void;
}) {
  const router = useRouter();
  const { addProfile, setActiveProfile } = useProfiles();
  const [hostname, setHostname] = useState("");
  const [username, setUsername] = useState("");
  const [port, setPort] = useState("22");
  const [remoteHost, setRemoteHost] = useState("127.0.0.1");
  const [remotePort, setRemotePort] = useState("38886");
  const [label, setLabel] = useState("");
  const [key, setKey] = useState<{ name: string; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pickKey = async () => {
    setBusy(true);
    onBusyChange(true);
    setError(null);
    try {
      const result = await DocumentPicker.getDocumentAsync({
        copyToCacheDirectory: true,
        multiple: false,
      });
      if (result.canceled) return;
      const asset = result.assets[0];
      if (!asset) throw new Error("No private key was selected.");
      const file = new File(asset.uri);
      try {
        if (file.size > 65536)
          throw new Error("Private keys must be 64 KiB or smaller.");
        const text = await file.text();
        if (!text.trim() || new TextEncoder().encode(text).length > 65536) {
          throw new Error("Select a private key of 64 KiB or smaller.");
        }
        setKey({ name: asset.name, text });
      } finally {
        file.delete();
      }
    } catch (cause) {
      setError(describeError(cause));
    } finally {
      setBusy(false);
      onBusyChange(false);
    }
  };

  const save = async () => {
    setBusy(true);
    onBusyChange(true);
    setError(null);
    let orphanKey: string | null = null;
    try {
      const host = validateHost(hostname, "SSH hostname");
      const targetHost = validateHost(remoteHost, "bb hostname");
      const user = username.trim();
      if (!user || /[\s\x00-\x1f\x7f]/.test(user))
        throw new Error("Enter a valid SSH username.");
      const sshPort = parsePort(port, "SSH port");
      const bbPort = parsePort(remotePort, "bb port");
      if (!key) throw new Error("Select an SSH private key.");
      const keyEncrypted = isSshPrivateKeyEncrypted(key.text);
      const localHost = await allocateSshLocalHost();
      orphanKey = await importSshKey(key.text);
      const profile = await addProfile({
        mode: "ssh",
        hostname: host,
        port: sshPort,
        username: user,
        keyRef: orphanKey,
        keyEncrypted,
        hostKey: null,
        localHost,
        remoteHost: targetHost,
        remotePort: bbPort,
        serverUrl: sshServerUrl(host, sshPort),
        label: (label.trim() || `${user}@${host}`).slice(
          0,
          PROFILE_LABEL_MAX_LENGTH,
        ),
      });
      orphanKey = null;
      setKey(null);
      await setActiveProfile(profile.id);
      toast.success(`Added ${profile.label}`);
      router.dismissTo("/");
      if (next?.startsWith("/")) router.push(rawPathHref(next));
    } catch (cause) {
      if (orphanKey) await deleteSshKey(orphanKey).catch(() => undefined);
      setError(describeError(cause));
    } finally {
      setBusy(false);
      onBusyChange(false);
    }
  };

  return (
    <>
      <SettingsSection
        title="SSH server"
        footnote="Connect through SSH using a private key. You’ll verify the server’s host key when connecting."
      >
        {[
          {
            value: hostname,
            set: setHostname,
            placeholder: "SSH hostname",
            id: "hostname",
          },
          {
            value: username,
            set: setUsername,
            placeholder: "SSH username",
            id: "username",
          },
          { value: port, set: setPort, placeholder: "SSH port", id: "port" },
          {
            value: label,
            set: setLabel,
            placeholder: "Label (optional)",
            id: "label",
          },
        ].map((field) => (
          <View className="px-1" key={field.id}>
            <Input
              value={field.value}
              onChangeText={field.set}
              placeholder={field.placeholder}
              autoCapitalize="none"
              autoCorrect={false}
              grouped
              editable={!busy}
              keyboardType={field.id === "port" ? "number-pad" : "default"}
              maxLength={
                field.id === "label" ? PROFILE_LABEL_MAX_LENGTH : undefined
              }
              testID={`ssh-${field.id}-input`}
            />
          </View>
        ))}
      </SettingsSection>
      <SettingsSection
        title="bb server on the SSH host"
        footnote="The address and port SSH forwards to, as seen from your SSH server."
      >
        <View className="px-1">
          <Input
            value={remoteHost}
            onChangeText={setRemoteHost}
            placeholder="bb hostname"
            autoCapitalize="none"
            autoCorrect={false}
            grouped
            editable={!busy}
            testID="ssh-remote-host-input"
          />
        </View>
        <View className="px-1">
          <Input
            value={remotePort}
            onChangeText={setRemotePort}
            placeholder="bb port"
            keyboardType="number-pad"
            grouped
            editable={!busy}
            testID="ssh-remote-port-input"
          />
        </View>
      </SettingsSection>
      <SettingsSection footnote="Your private key is stored securely on this phone. Encrypted keys prompt for their passphrase when connecting.">
        <Button
          onPress={() => void pickKey()}
          disabled={busy}
          testID="ssh-pick-key"
        >
          {key ? `Private key: ${key.name}` : "Choose private key file"}
        </Button>
      </SettingsSection>
      <Button
        onPress={() => void save()}
        loading={busy}
        disabled={!key || !hostname.trim() || !username.trim()}
        testID="ssh-add-submit"
      >
        Connect
      </Button>
      {error ? (
        <Text
          variant="footnote"
          tone="destructive"
          className="px-4"
          selectable
          testID="ssh-add-error"
        >
          {error}
        </Text>
      ) : null}
    </>
  );
}
