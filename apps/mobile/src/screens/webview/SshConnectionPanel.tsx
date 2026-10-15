import { useEffect, useState } from "react";
import { View } from "react-native";
import { useRouter } from "expo-router";
import { revealApp } from "@/app-shell";
import { getActiveProfileConnector } from "@/app-shell/connector";
import type { SshConnectionState } from "@/lib/ssh/transport";
import { Button, Input, Spinner, Text } from "@/ui";

export function SshConnectionPanel({
  label,
  hostname,
  port,
  state,
}: {
  label: string;
  hostname: string;
  port: number;
  state: SshConnectionState | null;
}) {
  const router = useRouter();
  const connector = getActiveProfileConnector();
  const [passphrase, setPassphrase] = useState("");
  useEffect(() => {
    revealApp();
  }, []);
  const submitPassphrase = () => {
    connector.provideSshPassphrase(passphrase);
    setPassphrase("");
  };
  return (
    <View
      className="flex-1 justify-center gap-4 p-6"
      testID="ssh-connection-panel"
    >
      <Text variant="heading" weight="semibold">
        {label}
      </Text>
      {state?.status === "host-key-confirmation" ? (
        <>
          <Text>Trust this SSH server?</Text>
          <Text selectable>
            {hostname}:{port}
          </Text>
          <Text selectable testID="ssh-host-fingerprint">
            {state.fingerprint}
          </Text>
          <Text variant="footnote">
            Compare this fingerprint with the server’s host key before trusting
            it.
          </Text>
          <Button
            onPress={() => connector.confirmSshHostKey(true)}
            testID="ssh-trust-host"
          >
            Trust and connect
          </Button>
          <Button
            variant="ghost"
            onPress={() => connector.confirmSshHostKey(false)}
          >
            Reject
          </Button>
        </>
      ) : state?.status === "passphrase-needed" ? (
        <>
          <Text variant="footnote">{state.detail}</Text>
          <Input
            value={passphrase}
            onChangeText={setPassphrase}
            secureTextEntry
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="Key passphrase (optional)"
            onSubmitEditing={submitPassphrase}
            testID="ssh-passphrase"
          />
          <Button onPress={submitPassphrase} testID="ssh-connect">
            Connect
          </Button>
        </>
      ) : state?.status === "error" ? (
        <>
          <Text tone="destructive" selectable testID="ssh-error">
            {state.detail}
          </Text>
          <Button onPress={() => connector.retrySsh()} testID="ssh-retry">
            Try again
          </Button>
        </>
      ) : (
        <>
          <Spinner />
          <Text>
            {state?.status === "suspended"
              ? "Connection paused while the app is in the background."
              : "Connecting over SSH…"}
          </Text>
        </>
      )}
      <Button
        variant="ghost"
        onPress={() => router.push("/settings/servers")}
        testID="ssh-select-server"
      >
        Choose a server
      </Button>
    </View>
  );
}
