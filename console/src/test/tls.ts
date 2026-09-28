import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

/**
 * Throwaway self-signed certificate for `localhost` / `127.0.0.1` (test TLS servers), made with
 * the `openssl` CLI. `null` when openssl is unavailable (the TLS tests are then skipped with a
 * message).
 */
export function selfSignedCert(): { key: string; cert: string } | null {
  const dir = mkdtempSync(path.join(tmpdir(), "databastion-tls-"));
  try {
    const cfg = path.join(dir, "req.cnf");
    writeFileSync(
      cfg,
      [
        "[req]",
        "distinguished_name = dn",
        "x509_extensions = ext",
        "prompt = no",
        "[dn]",
        "CN = localhost",
        "[ext]",
        "subjectAltName = DNS:localhost,IP:127.0.0.1",
        "basicConstraints = critical,CA:TRUE",
      ].join("\n"),
    );
    const res = spawnSync(
      "openssl",
      ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-keyout", path.join(dir, "key.pem"), "-out", path.join(dir, "cert.pem"), "-config", cfg],
      { encoding: "utf8", timeout: 20_000 },
    );
    if (res.status !== 0) return null;
    return { key: readFileSync(path.join(dir, "key.pem"), "utf8"), cert: readFileSync(path.join(dir, "cert.pem"), "utf8") };
  } catch {
    return null;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
