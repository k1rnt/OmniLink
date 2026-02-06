import { createContext, useContext, useCallback } from "react";

export type ToastType = "success" | "error" | "warning";

export interface Toast {
  id: number;
  message: string;
  type: ToastType;
}

export interface ToastContextType {
  toasts: Toast[];
  addToast: (message: string, type?: ToastType) => void;
  removeToast: (id: number) => void;
}

export const ToastContext = createContext<ToastContextType>({
  toasts: [],
  addToast: () => {},
  removeToast: () => {},
});

export function useToast() {
  const ctx = useContext(ToastContext);
  const success = useCallback((msg: string) => ctx.addToast(msg, "success"), [ctx]);
  const error = useCallback((msg: string) => ctx.addToast(msg, "error"), [ctx]);
  const warning = useCallback((msg: string) => ctx.addToast(msg, "warning"), [ctx]);
  return { toast: ctx.addToast, success, error, warning };
}
