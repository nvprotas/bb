import { z } from "zod";

export const PROFILE_LABEL_MAX_LENGTH = 64;

const profileBaseSchema = z.object({
  id: z.string().min(1),
  serverUrl: z.string().url(),
  label: z.string().min(1).max(PROFILE_LABEL_MAX_LENGTH),
  createdAt: z.number().int().nonnegative(),
});

const directServerProfileSchema = profileBaseSchema
  .extend({ mode: z.literal("direct") })
  .strict();

const connectServerProfileSchema = profileBaseSchema
  .extend({
    mode: z.literal("connect"),
    handle: z.string().min(1),
    credential: z.string().min(1),
  })
  .strict();

const sshServerProfileSchema = profileBaseSchema
  .extend({
    mode: z.literal("ssh"),
    hostname: z
      .string()
      .min(1)
      .max(253)
      .regex(/^[a-zA-Z0-9.:-]+$/),
    port: z.number().int().min(1).max(65535),
    username: z.string().min(1).max(128),
    keyRef: z.string().min(1).max(128),
    keyEncrypted: z.boolean().default(true),
    hostKey: z.string().max(1024).nullable(),
    localHost: z
      .string()
      .regex(
        /^127\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
      ),
    remoteHost: z
      .string()
      .min(1)
      .max(253)
      .regex(/^[a-zA-Z0-9.:-]+$/),
    remotePort: z.number().int().min(1).max(65535),
  })
  .strict();

export const serverProfileSchema = z.discriminatedUnion("mode", [
  directServerProfileSchema,
  connectServerProfileSchema,
  sshServerProfileSchema,
]);

export type DirectServerProfile = z.infer<typeof directServerProfileSchema>;
export type ConnectServerProfile = z.infer<typeof connectServerProfileSchema>;
export type SshServerProfile = z.infer<typeof sshServerProfileSchema>;
export type ServerProfile = z.infer<typeof serverProfileSchema>;
export type NewServerProfile =
  | Omit<DirectServerProfile, "id" | "createdAt">
  | Omit<ConnectServerProfile, "id" | "createdAt">
  | Omit<SshServerProfile, "id" | "createdAt">;

export type ServerProfilePatch = Partial<
  Pick<ConnectServerProfile, "label" | "serverUrl" | "handle" | "credential"> &
    Pick<SshServerProfile, "hostKey">
>;
