import type { JsonPatchOperation } from "./gen/admin/v1/admin.js";

// Small ergonomic constructors for admin.v1.JsonPatchOperation -- writing the
// {op, path, from, value} shape out by hand at every PatchServiceConfig call
// site is exactly the kind of friction this package's other helpers (dialAdmin,
// authInterceptor, ...) already exist to smooth over. `from` is only meaningful
// for "move"/"copy" (RFC 6902 section 4); every other op leaves it "".

/** Appends `value` to the end of the array at `path` (a trailing "/-" per RFC 6901/6902 -- no
 * read of the array's current length needed). */
export function jsonPatchAppend(path: string, value: unknown): JsonPatchOperation {
  return { op: "add", path: `${path}/-`, from: "", value };
}

/** Sets `value` at an exact `path` -- creates it if absent, per RFC 6902's "add" semantics. */
export function jsonPatchAdd(path: string, value: unknown): JsonPatchOperation {
  return { op: "add", path, from: "", value };
}

/** Overwrites the existing value at `path`. Fails if `path` doesn't already exist. */
export function jsonPatchReplace(path: string, value: unknown): JsonPatchOperation {
  return { op: "replace", path, from: "", value };
}

/** Removes the value at `path`. Fails if `path` doesn't exist. */
export function jsonPatchRemove(path: string): JsonPatchOperation {
  return { op: "remove", path, from: "", value: undefined };
}

/** Asserts the current value at `path` equals `value`, or the whole patch fails with no
 * partial effect (RFC 6902 section 4.6) -- a concurrency guard: fail the call cleanly rather
 * than silently overwrite/remove something a concurrent writer already changed. */
export function jsonPatchTest(path: string, value: unknown): JsonPatchOperation {
  return { op: "test", path, from: "", value };
}
