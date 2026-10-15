import { NativeModule, requireOptionalNativeModule } from "expo-modules-core";

export type SshOpenOptions = {
  attemptId: string;
  hostname: string;
  port: number;
  username: string;
  keyRef: string;
  passphrase: string | null;
  hostKey: string | null;
  localHost: string;
  remoteHost: string;
  remotePort: number;
};

export type SshEvents = {
  onState: (event: { attemptId: string; state: string }) => void;
  onHostKey: (event: {
    attemptId: string;
    hostKey: string;
    fingerprint: string;
    changed: boolean;
  }) => void;
  onClosed: (event: {
    attemptId: string;
    message: string;
    code: string;
  }) => void;
};

declare class BbSshModule extends NativeModule<SshEvents> {
  importKey(privateKey: string): Promise<string>;
  deleteKey(keyRef: string): Promise<void>;
  open(
    options: SshOpenOptions,
  ): Promise<{ tunnelId: string; serverUrl: string; tunnelSecret: string }>;
  restoreCookie(tunnelId: string): Promise<void>;
  confirmHostKey(attemptId: string, accept: boolean): Promise<void>;
  cancel(attemptId: string): Promise<void>;
  close(tunnelId: string): Promise<void>;
}

export default requireOptionalNativeModule<BbSshModule>("BbSsh");
