import assert from "node:assert/strict";
import { test } from "node:test";
import { jsonPatchAdd, jsonPatchAppend, jsonPatchRemove, jsonPatchReplace, jsonPatchTest } from "./jsonpatch.js";

test("jsonPatchAppend adds a trailing /- to the path", () => {
  assert.deepEqual(jsonPatchAppend("/tenants/acme/sessionKeyGenerations", { version: 2 }), {
    op: "add",
    path: "/tenants/acme/sessionKeyGenerations/-",
    from: "",
    value: { version: 2 },
  });
});

test("jsonPatchAdd uses the exact path given", () => {
  assert.deepEqual(jsonPatchAdd("/tenants/acme/seatLimit", 10), {
    op: "add",
    path: "/tenants/acme/seatLimit",
    from: "",
    value: 10,
  });
});

test("jsonPatchReplace", () => {
  assert.deepEqual(jsonPatchReplace("/tenants/acme/name", "New Name"), {
    op: "replace",
    path: "/tenants/acme/name",
    from: "",
    value: "New Name",
  });
});

test("jsonPatchRemove has no value", () => {
  assert.deepEqual(jsonPatchRemove("/tenants/acme/sessionKeyGenerations/0"), {
    op: "remove",
    path: "/tenants/acme/sessionKeyGenerations/0",
    from: "",
    value: undefined,
  });
});

test("jsonPatchTest asserts a value at a path", () => {
  assert.deepEqual(jsonPatchTest("/tenants/acme/sessionKeyGenerations/0/version", 1), {
    op: "test",
    path: "/tenants/acme/sessionKeyGenerations/0/version",
    from: "",
    value: 1,
  });
});
