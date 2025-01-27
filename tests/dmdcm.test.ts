import { describe, expect, it } from "vitest";
import { Cl } from "@stacks/transactions";

const accounts = simnet.getAccounts();
const patient = accounts.get("wallet_1")!;
const provider = accounts.get("wallet_2")!;

describe("dmdcm contract", () => {
  it("allows patients to grant consent", () => {
    const grantCall = simnet.callPublicFn(
      "dmdcm",
      "grant-consent",
      [Cl.principal(provider)],
      patient
    );
    expect(grantCall.result).toBeOk(Cl.bool(true));

    const checkCall = simnet.callReadOnlyFn(
      "dmdcm",
      "check-consent",
      [Cl.principal(patient), Cl.principal(provider)],
      patient
    );
    expect(checkCall.result).toStrictEqual(
      Cl.tuple({
        authorized: Cl.bool(true),
        timestamp: Cl.uint(simnet.blockHeight),
      })
    );
  });

  it("allows patients to revoke consent", () => {
    // First grant consent
    simnet.callPublicFn(
      "dmdcm",
      "grant-consent",
      [Cl.principal(provider)],
      patient
    );

    // Then revoke it
    const revokeCall = simnet.callPublicFn(
      "dmdcm",
      "revoke-consent",
      [Cl.principal(provider)],
      patient
    );
    expect(revokeCall.result).toBeOk(Cl.bool(true));

    const checkCall = simnet.callReadOnlyFn(
      "dmdcm",
      "check-consent",
      [Cl.principal(patient), Cl.principal(provider)],
      patient
    );
    expect(checkCall.result).toStrictEqual(
      Cl.tuple({
        authorized: Cl.bool(false),
        timestamp: Cl.uint(simnet.blockHeight),
      })
    );
  });
});
