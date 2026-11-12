export type DecisionTone = "allow" | "deny" | "pending";

export function decisionTone(value: string): DecisionTone {
  if (value.startsWith("ALLOW")) return "allow";
  if (value.startsWith("APPROVAL_REQUIRED")) return "pending";
  return "deny";
}
