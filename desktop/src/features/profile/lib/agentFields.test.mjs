import assert from "node:assert/strict";
import test from "node:test";

import { agentFieldRows } from "./agentFields.ts";

const field = (key, value, extra = {}) => ({
  key,
  value,
  type: "text",
  visibility: "community",
  createdAt: 1,
  ...extra,
});

test("agentFieldRows orders reserved keys first and formats their values", () => {
  const rows = agentFieldRows([
    field("focus", "triage"),
    field("cost", "0.4121", { visibility: "owner" }),
    field("context", "41250/200000"),
    field("model", "opus"),
    field("transcript", "{}", { type: "transcript" }),
    field("harness", "goose"),
  ]);
  assert.deepEqual(
    rows.map(({ label, value, ownerOnly }) => [label, value, ownerOnly]),
    [
      ["Harness", "goose", false],
      ["Model", "opus", false],
      ["Context", "41k / 200k", false],
      ["Cost", "$0.41", true],
      ["Transcript", "Transcript available", false],
      ["focus", "triage", false],
    ],
  );
});

test("agentFieldRows keeps malformed reserved values as raw text", () => {
  assert.deepEqual(
    agentFieldRows([field("context", "lots"), field("cost", "n/a")]).map(
      (row) => row.value,
    ),
    ["lots", "n/a"],
  );
});
