import { describe, expect, it } from "vitest";
import { decisionTone } from "./decision";

describe("decisionTone", () => {
  it("distinguishes allows, denials, and approval holds", () => {
    expect(decisionTone("ALLOW:AUTHORIZED")).toBe("allow");
    expect(decisionTone("DENY:CROSS_TENANT")).toBe("deny");
    expect(decisionTone("APPROVAL_REQUIRED:HUMAN_APPROVAL_REQUIRED")).toBe(
      "pending",
    );
  });

  it("fails unknown dispositions closed", () => {
    expect(decisionTone("unexpected")).toBe("deny");
  });
});
