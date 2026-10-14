export type SecretStorage = "keychain" | "plaintextFile";

export function usesPlaintextFallback(
  storage: SecretStorage | null | undefined,
): boolean {
  return storage === "plaintextFile";
}
