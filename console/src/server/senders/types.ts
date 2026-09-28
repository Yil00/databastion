/** Outcome of one delivery attempt: `code` is a closed error code (never a server response). */
export type SendResult = { ok: true } | { ok: false; code: string; retryable: boolean };
