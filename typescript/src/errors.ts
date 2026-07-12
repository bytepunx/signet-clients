// Small error-handling helpers shared across the library. The goal
// throughout this package is that every rejected Promise carries a message
// that is specific and actionable on its own, without the caller needing to
// inspect a wrapped cause or a raw gRPC/OpenSSL stack trace.

/** Coerces an unknown thrown/rejected value into a proper Error. */
export function asError(err: unknown): Error {
  if (err instanceof Error) return err;
  return new Error(String(err));
}

/** Extracts a human-readable message from an unknown thrown/rejected value. */
export function errMessage(err: unknown): string {
  return asError(err).message;
}

/**
 * Builds an Error describing an AbortSignal-triggered cancellation, using the
 * signal's `reason` when the caller supplied one (e.g. via
 * `controller.abort(new Error("shutting down"))`).
 */
export function abortedError(signal: AbortSignal | undefined, context: string): Error {
  const reason = signal?.reason;
  if (reason instanceof Error) {
    return new Error(`signet: ${context}: aborted: ${reason.message}`);
  }
  if (reason !== undefined && reason !== null) {
    return new Error(`signet: ${context}: aborted: ${String(reason)}`);
  }
  return new Error(`signet: ${context}: aborted`);
}

/** Internal marker thrown by raceAbort when the signal fires first. */
export class AbortRaceError extends Error {}

/**
 * Races an arbitrary Promise against an AbortSignal, rejecting with
 * AbortRaceError the moment the signal fires — even if the original promise
 * never settles on its own. Without this, an abstract, transport-agnostic
 * `recv()`-style Promise that a fake/test double never resolves would hang
 * a caller forever regardless of the signal, since only the real gRPC
 * adapter ties cancellation into the underlying stream.
 */
export function raceAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new AbortRaceError("aborted"));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new AbortRaceError("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (err) => {
        signal.removeEventListener("abort", onAbort);
        reject(err);
      },
    );
  });
}
