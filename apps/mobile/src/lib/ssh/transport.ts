export interface SshOpenOptions {
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
}

export interface SshHostKeyEvent {
  attemptId: string;
  hostKey: string;
  fingerprint: string;
  changed: boolean;
}

export interface SshTransport {
  open(
    options: SshOpenOptions,
  ): Promise<{ tunnelId: string; serverUrl: string }>;
  confirmHostKey(options: {
    attemptId: string;
    accept: boolean;
  }): Promise<void>;
  cancel(options: { attemptId: string }): Promise<void>;
  close(options: { tunnelId: string }): Promise<void>;
  onState(
    listener: (event: {
      attemptId: string;
      state: string;
      detail?: string;
    }) => void,
  ): () => void;
  onHostKey(listener: (event: SshHostKeyEvent) => void): () => void;
  onClosed(
    listener: (event: {
      attemptId: string;
      tunnelId?: string;
      detail?: string;
      code?: string;
    }) => void,
  ): () => void;
}

export type SshConnectionState =
  | { status: "connecting" }
  | {
      status: "host-key-confirmation";
      hostKey: string;
      fingerprint: string;
      changed: boolean;
    }
  | { status: "passphrase-needed"; detail: string }
  | { status: "ready"; tunnelId: string; serverUrl: string }
  | { status: "error"; detail: string }
  | { status: "suspended" };
