import { describe, expect, it } from "vitest";

import { agentTokensHold, AGENT_TOKENS_HOLD_RELEASES, ConfigError, getDatabaseUrl, readEnvOrFile, requireEnvOrFile } from "./env";

const SECRET_URL = "postgresql://databastion:s3cr3t-pw@db:5432/databastion";

function fakeFs(files: Record<string, string>) {
  return (path: string): string => {
    const content = files[path];
    if (content === undefined) {
      throw Object.assign(new Error(`ENOENT: ${path}`), { code: "ENOENT" });
    }
    return content;
  };
}

describe("readEnvOrFile", () => {
  it("returns undefined when neither variable is set", () => {
    expect(readEnvOrFile("DATABASE_URL", {}, fakeFs({}))).toBeUndefined();
  });

  it("reads the direct environment variable", () => {
    expect(readEnvOrFile("DATABASE_URL", { DATABASE_URL: SECRET_URL }, fakeFs({}))).toBe(
      SECRET_URL,
    );
  });

  it("reads the file referenced by NAME_FILE and trims the trailing newline", () => {
    const env = { DATABASE_URL_FILE: "/run/secrets/db_url" };
    const fs = fakeFs({ "/run/secrets/db_url": `${SECRET_URL}\n` });
    expect(readEnvOrFile("DATABASE_URL", env, fs)).toBe(SECRET_URL);
  });

  it("treats an empty NAME_FILE as unset", () => {
    const env = { DATABASE_URL: SECRET_URL, DATABASE_URL_FILE: "" };
    expect(readEnvOrFile("DATABASE_URL", env, fakeFs({}))).toBe(SECRET_URL);
  });

  it("rejects ambiguous configuration when both are set", () => {
    const env = { DATABASE_URL: SECRET_URL, DATABASE_URL_FILE: "/run/secrets/db_url" };
    const fs = fakeFs({ "/run/secrets/db_url": SECRET_URL });
    expect(() => readEnvOrFile("DATABASE_URL", env, fs)).toThrow(ConfigError);
  });

  it("rejects an empty secret file", () => {
    const env = { DATABASE_URL_FILE: "/run/secrets/db_url" };
    const fs = fakeFs({ "/run/secrets/db_url": "  \n" });
    expect(() => readEnvOrFile("DATABASE_URL", env, fs)).toThrow(/is empty/);
  });

  it("reports an unreadable file without leaking its content or path", () => {
    const env = { DATABASE_URL_FILE: "/run/secrets/missing" };
    expect(() => readEnvOrFile("DATABASE_URL", env, fakeFs({}))).toThrow(
      "Cannot read the file referenced by DATABASE_URL_FILE (ENOENT).",
    );
  });
});

describe("requireEnvOrFile", () => {
  it("throws a ConfigError naming both variables when missing", () => {
    expect(() => requireEnvOrFile("DATABASTION_ENCRYPTION_KEY", {}, fakeFs({}))).toThrow(
      "Missing configuration: set DATABASTION_ENCRYPTION_KEY or DATABASTION_ENCRYPTION_KEY_FILE.",
    );
  });
});

describe("getDatabaseUrl", () => {
  it("accepts postgres:// and postgresql:// URLs", () => {
    expect(getDatabaseUrl({ DATABASE_URL: SECRET_URL }, fakeFs({}))).toBe(SECRET_URL);
    const short = "postgres://u:p@localhost/db";
    expect(getDatabaseUrl({ DATABASE_URL: short }, fakeFs({}))).toBe(short);
  });

  it.each([
    ["not a URL", "not a url s3cr3t-pw"],
    ["another scheme", "mysql://databastion:s3cr3t-pw@db/databastion"],
  ])("rejects %s without echoing the value", (_label, value) => {
    let message = "";
    try {
      getDatabaseUrl({ DATABASE_URL: value }, fakeFs({}));
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      message = (err as Error).message;
    }
    expect(message).not.toBe("");
    expect(message).not.toContain("s3cr3t-pw");
  });
});

describe("agentTokensHold (DATABASTION_AGENT_TOKENS_HOLD, ADR-0022 decision 8)", () => {
  const hold = (v: string | undefined) => agentTokensHold({ DATABASTION_AGENT_TOKENS_HOLD: v });

  it("is null when unset, empty or blank (no hold)", () => {
    expect(agentTokensHold({})).toBeNull();
    expect(hold(undefined)).toBeNull();
    expect(hold("")).toBeNull();
    expect(hold("  ")).toBeNull();
  });

  it("accepts each known release line, trimmed", () => {
    expect(AGENT_TOKENS_HOLD_RELEASES).toEqual(["0.8"]);
    expect(hold("0.8")).toBe("0.8");
    expect(hold(" 0.8\n")).toBe("0.8");
  });

  it("refuses any other value without echoing it (fail closed: the processes refuse to start)", () => {
    const message =
      "DATABASTION_AGENT_TOKENS_HOLD must be unset or one of: 0.8 (the release line of the oldest console replica).";
    for (const v of ["0.8.2", "0.8.0", "v0.8", "0.7", "0.9", "1", "true", "0.8,0.9", "0,8", "08"]) {
      expect(() => hold(v), v).toThrow(new ConfigError(message));
    }
  });
});
