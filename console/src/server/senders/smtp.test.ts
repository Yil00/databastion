import net from "node:net";
import tls from "node:tls";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { EmailConfig } from "@/lib/notification-model";
import { selfSignedCert } from "@/test/tls";

import { buildMessage, dataPayload, sendMail } from "./smtp";

interface Mail {
  from: string;
  rcpts: string[];
  data: string;
  auth: string | null;
  tls: boolean;
}

/**
 * In-process SMTP server for the tests: EHLO, optional STARTTLS (self-signed certificate), AUTH
 * PLAIN / LOGIN, MAIL, RCPT, DATA. Every accepted message is recorded.
 */
class FakeSmtp {
  mails: Mail[] = [];
  commands: string[] = [];
  private server: net.Server;
  port = 0;

  constructor(
    private readonly opts: {
      cert?: { key: string; cert: string } | null;
      implicitTls?: boolean;
      auth?: { user: string; pass: string };
      rcptReply?: string;
      silent?: boolean;
    } = {},
  ) {
    const onSocket = (socket: net.Socket, secure: boolean) => this.session(socket, secure);
    this.server = opts.implicitTls && opts.cert
      ? tls.createServer({ key: opts.cert.key, cert: opts.cert.cert }, (s) => onSocket(s, true))
      : net.createServer((s) => onSocket(s, false));
  }

  async start(): Promise<number> {
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", r));
    this.port = (this.server.address() as net.AddressInfo).port;
    return this.port;
  }

  stop(): Promise<void> {
    return new Promise((r) => this.server.close(() => r()));
  }

  private session(initial: net.Socket, initiallySecure: boolean): void {
    let socket = initial;
    let secure = initiallySecure;
    let buf = "";
    let inData = false;
    let mail: Mail = { from: "", rcpts: [], data: "", auth: null, tls: secure };
    let loginStep: 0 | 1 | 2 = 0;
    let loginUser = "";
    const send = (line: string) => socket.write(`${line}\r\n`);
    const onLine = (line: string) => {
      if (inData) {
        if (line === ".") {
          inData = false;
          this.mails.push(mail);
          mail = { from: "", rcpts: [], data: "", auth: mail.auth, tls: secure };
          send("250 queued");
        } else {
          mail.data += `${line.startsWith("..") ? line.slice(1) : line}\r\n`;
        }
        return;
      }
      this.commands.push(line.startsWith("AUTH") || loginStep > 0 ? "<auth>" : line);
      if (loginStep === 1) {
        loginUser = Buffer.from(line, "base64").toString("utf8");
        loginStep = 2;
        send("334 UGFzc3dvcmQ6");
        return;
      }
      if (loginStep === 2) {
        loginStep = 0;
        const pass = Buffer.from(line, "base64").toString("utf8");
        const ok = this.opts.auth && loginUser === this.opts.auth.user && pass === this.opts.auth.pass;
        if (ok) mail.auth = loginUser;
        send(ok ? "235 ok" : "535 bad credentials");
        return;
      }
      const verb = line.split(" ")[0]?.toUpperCase();
      if (verb === "EHLO") {
        const caps = ["250-fake.test"];
        if (this.opts.cert && !secure && !this.opts.implicitTls) caps.push("250-STARTTLS");
        if (this.opts.auth) caps.push("250-AUTH LOGIN");
        caps.push("250 8BITMIME");
        socket.write(caps.map((c) => `${c}\r\n`).join(""));
      } else if (verb === "STARTTLS" && this.opts.cert) {
        send("220 go ahead");
        socket.removeAllListeners("data");
        const secureSocket = new tls.TLSSocket(socket, { isServer: true, key: this.opts.cert.key, cert: this.opts.cert.cert });
        socket = secureSocket;
        secure = true;
        mail.tls = true;
        buf = "";
        secureSocket.setEncoding("utf8");
        secureSocket.on("data", onData);
        secureSocket.on("error", () => undefined);
      } else if (verb === "AUTH" && line.toUpperCase().startsWith("AUTH LOGIN")) {
        loginStep = 1;
        send("334 VXNlcm5hbWU6");
      } else if (verb === "MAIL") {
        mail.from = line.slice(10);
        send("250 ok");
      } else if (verb === "RCPT") {
        mail.rcpts.push(line.slice(8));
        send(this.opts.rcptReply ?? "250 ok");
      } else if (verb === "DATA") {
        inData = true;
        send("354 end with .");
      } else if (verb === "QUIT") {
        send("221 bye");
        socket.end();
      } else {
        send("502 not implemented");
      }
    };
    const onData = (chunk: string) => {
      buf += chunk;
      let i: number;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        onLine(line);
      }
    };
    socket.setEncoding("utf8");
    socket.on("data", onData);
    socket.on("error", () => undefined);
    if (!this.opts.silent) send("220 fake.test ESMTP");
  }
}

const MSG = {
  deliveryId: "01890a5d-ac96-774b-bcce-b302099a8057",
  event: "incident.opened",
  subject: "[DataBastion] HIGH incident: Données clients – e-mails",
  text: "A new incident was opened.\n.leading dot line\nOpen in the console: https://console.example.com/incidents/x\n",
};

const config = (port: number, over: Partial<EmailConfig> = {}): EmailConfig => ({
  host: "127.0.0.1",
  port,
  tls: "none",
  from: "dlp@example.com",
  recipients: ["soc@example.com", "ciso@example.com"],
  username: null,
  ...over,
});

function decodeBody(data: string): string {
  const body = data.split("\r\n\r\n").slice(1).join("\r\n\r\n");
  return Buffer.from(body.replace(/\r\n/g, ""), "base64").toString("utf8");
}

describe("SMTP message", () => {
  it("encodes a non-ASCII subject (RFC 2047), a base64 UTF-8 body, a stable Message-ID", () => {
    const m = buildMessage({ from: "a@example.com", recipients: ["b@example.com"] }, MSG, new Date("2026-09-28T12:00:00Z"));
    expect(m).toContain("Subject: =?UTF-8?B?");
    expect(m).toContain(`Message-ID: <${MSG.deliveryId}@databastion.invalid>`);
    expect(m).toContain("Auto-Submitted: auto-generated");
    expect(m).not.toMatch(/[^\r]\n/);
    const subject = /Subject: (.*(?:\r\n .*)*)/.exec(m)?.[1] ?? "";
    const decoded = subject
      .split(/\r\n /)
      .map((w) => Buffer.from(/=\?UTF-8\?B\?(.*)\?=/.exec(w)?.[1] ?? "", "base64").toString("utf8"))
      .join("");
    expect(decoded).toBe(MSG.subject);
    // A subject cannot inject headers.
    expect(buildMessage({ from: "a@example.com", recipients: ["b@example.com"] }, { ...MSG, subject: "x\r\nBcc: evil@example.com" })).not.toContain(
      "\r\nBcc:",
    );
  });

  it("dot-stuffs and terminates the data", () => {
    expect(dataPayload("a\r\n.b\r\n")).toBe("a\r\n..b\r\n.\r\n");
    expect(dataPayload(".x")).toBe("..x\r\n.\r\n");
  });
});

describe("SMTP sender against an in-process server", () => {
  const plain = new FakeSmtp();
  let port = 0;
  beforeAll(async () => {
    port = await plain.start();
  });
  afterAll(() => plain.stop());

  it("delivers in plain text to a loopback relay", async () => {
    expect(await sendMail(config(port), null, MSG, { allowInsecure: false })).toEqual({ ok: true });
    const mail = plain.mails.at(-1);
    expect(mail?.from).toBe("<dlp@example.com>");
    expect(mail?.rcpts).toEqual(["<soc@example.com>", "<ciso@example.com>"]);
    expect(decodeBody(mail?.data ?? "")).toBe(MSG.text.replace(/\n/g, "\r\n"));
  });

  it("refuses plain text towards a non-loopback address without the dev flag (no connection)", async () => {
    const resolver = async () => [{ address: "10.0.0.25", family: 4 }];
    const n = plain.commands.length;
    expect(await sendMail(config(port, { host: "relay.example" }), null, MSG, { allowInsecure: false, resolver })).toEqual({
      ok: false,
      code: "insecure_refused",
      retryable: false,
    });
    const meta = async () => [{ address: "169.254.169.254", family: 4 }];
    expect(await sendMail(config(port, { host: "relay.example", tls: "starttls" }), null, MSG, { allowInsecure: true, resolver: meta })).toMatchObject({
      code: "address_forbidden",
    });
    expect(plain.commands.length).toBe(n);
  });

  it("STARTTLS is required when configured: no silent downgrade", async () => {
    expect(await sendMail(config(port, { tls: "starttls" }), null, MSG, { allowInsecure: false })).toEqual({
      ok: false,
      code: "starttls_unavailable",
      retryable: false,
    });
  });

  it("a 5xx reply fails, a 4xx reply is retried", async () => {
    const reject = new FakeSmtp({ rcptReply: "550 no such user" });
    const busy = new FakeSmtp({ rcptReply: "451 try later" });
    const [p1, p2] = [await reject.start(), await busy.start()];
    try {
      expect(await sendMail(config(p1), null, MSG, { allowInsecure: false })).toEqual({ ok: false, code: "smtp_550", retryable: false });
      expect(await sendMail(config(p2), null, MSG, { allowInsecure: false })).toEqual({ ok: false, code: "smtp_451", retryable: true });
    } finally {
      await reject.stop();
      await busy.stop();
    }
  });

  it("times out on a server that never greets", async () => {
    const mute = new FakeSmtp({ silent: true });
    const p = await mute.start();
    try {
      expect(await sendMail(config(p), null, MSG, { allowInsecure: false, replyTimeoutMs: 200 })).toEqual({ ok: false, code: "timeout", retryable: true });
    } finally {
      await mute.stop();
    }
  });
});

const cert = selfSignedCert();
if (!cert) {
  // eslint-disable-next-line no-console -- test harness message
  console.warn("[smtp tests] STARTTLS / implicit TLS SKIPPED: openssl unavailable.");
}

describe.skipIf(!cert)("SMTP sender over TLS", () => {
  const starttls = new FakeSmtp({ cert, auth: { user: "dlp", pass: "s3cret pass" } });
  const implicit = new FakeSmtp({ cert, implicitTls: true });
  let p1 = 0;
  let p2 = 0;
  beforeAll(async () => {
    p1 = await starttls.start();
    p2 = await implicit.start();
  });
  afterAll(async () => {
    await starttls.stop();
    await implicit.stop();
  });

  it("upgrades with STARTTLS, verifies the certificate, then authenticates", async () => {
    const cfg = config(p1, { host: "localhost", tls: "starttls", username: "dlp" });
    expect(await sendMail(cfg, "s3cret pass", MSG, { allowInsecure: false, ca: cert?.cert })).toEqual({ ok: true });
    expect(starttls.mails.at(-1)).toMatchObject({ tls: true, auth: "dlp" });
    // The credentials never appear in clear on the wire before TLS (the server saw them inside TLS).
    expect(starttls.commands.filter((c) => c.includes("s3cret"))).toEqual([]);
    expect(await sendMail(cfg, "wrong", MSG, { allowInsecure: false, ca: cert?.cert })).toEqual({ ok: false, code: "smtp_535", retryable: false });
    // Untrusted certificate: refused.
    expect(await sendMail(cfg, "s3cret pass", MSG, { allowInsecure: false })).toEqual({ ok: false, code: "tls_failed", retryable: true });
  });

  it("implicit TLS", async () => {
    expect(await sendMail(config(p2, { host: "localhost", tls: "implicit" }), null, MSG, { allowInsecure: false, ca: cert?.cert })).toEqual({ ok: true });
    expect(implicit.mails.at(-1)?.tls).toBe(true);
  });
});

/**
 * Real SMTP server (Mailpit from dev/docker-compose.yml): `DATABASTION_TEST_SMTP=127.0.0.1:1025`
 * (and `DATABASTION_TEST_MAILPIT_API`, default `http://<host>:8025`). Skipped with a message when
 * unset or unreachable.
 */
const MAILPIT = process.env.DATABASTION_TEST_SMTP;
async function mailpitReachable(): Promise<boolean> {
  if (!MAILPIT) return false;
  const [host, port] = MAILPIT.split(":");
  return new Promise((resolve) => {
    const s = net.connect({ host, port: Number(port) }, () => {
      s.destroy();
      resolve(true);
    });
    s.once("error", () => resolve(false));
    s.setTimeout(2000, () => {
      s.destroy();
      resolve(false);
    });
  });
}
const mailpit = await mailpitReachable();
if (!mailpit) {
  // eslint-disable-next-line no-console -- test harness message
  console.warn(
    MAILPIT
      ? `[smtp tests] Mailpit SKIPPED: ${MAILPIT} unreachable (start it with \`make dev\`).`
      : "[smtp tests] Mailpit SKIPPED: set DATABASTION_TEST_SMTP=127.0.0.1:1025 (Mailpit from `make dev`) to run it.",
  );
}

describe.skipIf(!mailpit)("SMTP sender against Mailpit", () => {
  it("delivers a message that Mailpit receives", async () => {
    const [host = "127.0.0.1", port = "1025"] = String(MAILPIT).split(":");
    const api = process.env.DATABASTION_TEST_MAILPIT_API ?? `http://${host}:8025`;
    const deliveryId = crypto.randomUUID();
    const subject = `[DataBastion] test ${deliveryId}`;
    const res = await sendMail(
      { host, port: Number(port), tls: "none", from: "dlp@example.com", recipients: ["soc@example.com"], username: null },
      null,
      { deliveryId, event: "channel.test", subject, text: "Mailpit test." },
      { allowInsecure: true },
    );
    expect(res).toEqual({ ok: true });
    const search = await fetch(`${api}/api/v1/search?query=${encodeURIComponent(`subject:"${deliveryId}"`)}`);
    const found = (await search.json()) as { messages?: { Subject: string }[] };
    expect(found.messages?.map((m) => m.Subject)).toContain(subject);
  });
});
