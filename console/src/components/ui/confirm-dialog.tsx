"use client";

import { useRef, type ReactNode } from "react";

import { Button, type ButtonProps } from "./button";

/**
 * Confirmation dialog on the native `<dialog>` element (focus trap, Escape and backdrop handled by
 * the browser; no inline script or style, so it works under the strict CSP).
 */
export function ConfirmDialog({
  trigger,
  title,
  description,
  confirmLabel,
  variant = "default",
  disabled,
  onConfirm,
}: {
  trigger: string;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  variant?: ButtonProps["variant"];
  disabled?: boolean;
  onConfirm: () => void | Promise<void>;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  return (
    <>
      <Button variant={variant} size="sm" disabled={disabled} onClick={() => ref.current?.showModal()}>
        {trigger}
      </Button>
      <dialog
        ref={ref}
        aria-labelledby={`${confirmLabel}-title`}
        className="m-auto max-w-md rounded-xl border bg-background p-6 text-foreground shadow-lg backdrop:bg-black/50"
      >
        <h2 id={`${confirmLabel}-title`} className="text-lg font-semibold">
          {title}
        </h2>
        <div className="mt-2 text-sm text-muted-foreground">{description}</div>
        <div className="mt-6 flex justify-end gap-2">
          <Button variant="outline" onClick={() => ref.current?.close()}>
            Cancel
          </Button>
          <Button
            variant={variant}
            onClick={async () => {
              ref.current?.close();
              await onConfirm();
            }}
          >
            {confirmLabel}
          </Button>
        </div>
      </dialog>
    </>
  );
}
