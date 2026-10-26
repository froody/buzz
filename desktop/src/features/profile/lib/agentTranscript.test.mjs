import assert from "node:assert/strict";
import test from "node:test";

import {
  initialCursor,
  nextTranscriptStep,
  parseTranscriptManifest,
  showSegment,
  withPage,
} from "./agentTranscript.ts";

const seg = (sha256) => ({ sha256, size: 1, at: 1 });

test("loads newest segments first, then follows earlier pages", () => {
  const manifest = parseTranscriptManifest(
    JSON.stringify({ v: 1, segments: [seg("c"), seg("d")], earlier: "p1" }),
  );
  const pages = {
    p1: { v: 1, segments: [seg("a"), seg("b")], earlier: "p2" },
    p2: { v: 1, segments: [], earlier: null },
  };
  let cursor = initialCursor(manifest);
  const order = [];
  for (
    let step = nextTranscriptStep(cursor);
    step;
    step = nextTranscriptStep(cursor)
  ) {
    if (step.kind === "page") {
      order.push(`page:${step.sha256}`);
      cursor = withPage(cursor, pages[step.sha256]);
    } else {
      order.push(step.segment.sha256);
      cursor = showSegment(cursor);
    }
  }
  assert.deepEqual(order, ["d", "c", "page:p1", "b", "a", "page:p2"]);
  assert.equal(parseTranscriptManifest('{"v":2,"segments":[]}'), null);
});
