import type {
  AgentTranscriptManifest,
  AgentTranscriptSegment,
} from "@/shared/api/tauriAgentFields";

/** Segments known so far (oldest first), how many of the newest are shown, and the unread page. */
export type TranscriptCursor = {
  segments: AgentTranscriptSegment[];
  shown: number;
  earlier: string | null;
};

/** What "Load earlier" fetches next: an unshown segment, else the next older page. */
export type TranscriptStep =
  | { kind: "segment"; segment: AgentTranscriptSegment }
  | { kind: "page"; sha256: string }
  | null;

export function parseTranscriptManifest(
  value: string,
): AgentTranscriptManifest | null {
  try {
    const parsed = JSON.parse(value) as AgentTranscriptManifest;
    return parsed?.v === 1 && Array.isArray(parsed.segments) ? parsed : null;
  } catch {
    return null;
  }
}

export function initialCursor(
  manifest: AgentTranscriptManifest,
): TranscriptCursor {
  return {
    segments: manifest.segments,
    shown: 0,
    earlier: manifest.earlier ?? null,
  };
}

export function nextTranscriptStep(cursor: TranscriptCursor): TranscriptStep {
  const index = cursor.segments.length - cursor.shown - 1;
  if (index >= 0) {
    return { kind: "segment", segment: cursor.segments[index] };
  }
  return cursor.earlier ? { kind: "page", sha256: cursor.earlier } : null;
}

/** Record that the step's segment is now shown. */
export function showSegment(cursor: TranscriptCursor): TranscriptCursor {
  return { ...cursor, shown: cursor.shown + 1 };
}

/** Prepend an `earlier` page's (older) segments. */
export function withPage(
  cursor: TranscriptCursor,
  page: AgentTranscriptManifest,
): TranscriptCursor {
  return {
    segments: [...page.segments, ...cursor.segments],
    shown: cursor.shown,
    earlier: page.earlier ?? null,
  };
}
