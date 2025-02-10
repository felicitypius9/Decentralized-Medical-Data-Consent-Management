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
describe("Medical Data Consent System", () => {
  describe("Patient Registry", () => {
      it("allows patient registration", () => {
          const registerCall = simnet.callPublicFn(
              "dmdcm",
              "register-patient",
              [Cl.stringAscii("John Doe"), Cl.uint(19900101)],
              patient
          );
          expect(registerCall.result).toBeOk(Cl.bool(true));

          const infoCall = simnet.callReadOnlyFn(
              "dmdcm",
              "get-patient-info",
              [Cl.principal(patient)],
              patient
          );
          expect(infoCall.result).toStrictEqual(Cl.some(Cl.tuple({
              name: Cl.stringAscii("John Doe"),
              dob: Cl.uint(19900101),
              registered: Cl.uint(simnet.blockHeight)
          })));
      });
  });
});

  describe("Provider Registry", () => {
    it("handles provider lifecycle", () => {
      const registerCall = simnet.callPublicFn(
        "dmdcm",
        "register-provider",
        [Cl.stringAscii("Dr. Smith"), Cl.stringAscii("MED123456")],
        provider
      );
      expect(registerCall.result).toBeOk(Cl.bool(true));

      const deactivateCall = simnet.callPublicFn(
        "dmdcm",
        "deactivate-provider",
        [],
        provider
      );
      expect(deactivateCall.result).toBeOk(Cl.bool(true));
    });
  });

  describe("Access Logging", () => {
    it("logs access events", () => {
      const logCall = simnet.callPublicFn(
        "dmdcm",
        "log-access",
        [
          Cl.principal(patient),
          Cl.stringAscii("VIEW"),
          Cl.stringAscii("Accessed patient records"),
        ],
        provider
      );
      expect(logCall.result).toBeOk(Cl.bool(true));

      const countCall = simnet.callReadOnlyFn(
        "dmdcm",
        "get-log-count",
        [],
        provider
      );
      expect(countCall.result).toBeUint(1);
    });
  });

  describe("Consent Management", () => {
    it("integrates with other contracts", () => {
      // Register patient and provider first
      simnet.callPublicFn(
        "dmdcm",
        "register-patient",
        [Cl.stringAscii("John Doe"), Cl.uint(19900101)],
        patient
      );

      simnet.callPublicFn(
        "dmdcm",
        "register-provider",
        [Cl.stringAscii("Dr. Smith"), Cl.stringAscii("MED123456")],
        provider
      );

      // Grant consent
      const grantCall = simnet.callPublicFn(
        "dmdcm",
        "grant-consent",
        [Cl.principal(provider)],
        patient
      );
      expect(grantCall.result).toBeOk(Cl.bool(true));

      // Log access
      const logCall = simnet.callPublicFn(
        "dmdcm",
        "log-access",
        [
          Cl.principal(patient),
          Cl.stringAscii("ACCESS_GRANTED"),
          Cl.stringAscii("Initial consent granted"),
        ],
        provider
      );
      expect(logCall.result).toBeOk(Cl.bool(true));
    });
  });


  // TTT