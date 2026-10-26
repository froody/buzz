import * as React from "react";
import { CircleAlert } from "lucide-react";

import { unwrapObserverBatch } from "@/features/agents/observerRelayStore";
import { AgentSessionTranscriptList } from "@/features/agents/ui/AgentSessionTranscriptList";
import { buildTranscriptState } from "@/features/agents/ui/agentSessionTranscript";
import type {
  ObserverEvent,
  TranscriptItem,
} from "@/features/agents/ui/agentSessionTypes";
import {
  initialCursor,
  nextTranscriptStep,
  parseTranscriptManifest,
  showSegment,
  type TranscriptCursor,
  withPage,
} from "@/features/profile/lib/agentTranscript";
import {
  type AgentTranscriptSegment,
  readAgentTranscriptPage,
  readAgentTranscriptSegment,
} from "@/shared/api/tauriAgentFields";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Spinner } from "@/shared/ui/spinner";

type SegmentSlot = {
  segment: AgentTranscriptSegment;
  items: TranscriptItem[] | null;
  error: string | null;
};

function errorText(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

function InlineError({
  message,
  onRetry,
  retryLabel,
}: {
  message: string;
  onRetry: () => void;
  retryLabel: string;
}) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      <CircleAlert aria-hidden className="h-4 w-4 shrink-0" />
      <span className="min-w-0 flex-1">{message}</span>
      <Button
        aria-label={retryLabel}
        onClick={onRetry}
        size="xs"
        variant="outline"
      >
        Retry
      </Button>
    </div>
  );
}

type ViewerProps = {
  agentAvatarUrl: string | null;
  agentName: string;
  agentPubkey: string;
  manifest: string;
};

function TranscriptViewer({
  agentAvatarUrl,
  agentName,
  agentPubkey,
  manifest,
}: ViewerProps) {
  const parsed = React.useMemo(
    () => parseTranscriptManifest(manifest),
    [manifest],
  );
  const cursorRef = React.useRef<TranscriptCursor | null>(
    parsed ? initialCursor(parsed) : null,
  );
  // Newest first, in load order.
  const [slots, setSlots] = React.useState<SegmentSlot[]>([]);
  const [paging, setPaging] = React.useState(false);
  const [pageError, setPageError] = React.useState<string | null>(null);
  const [exhausted, setExhausted] = React.useState(false);

  const updateSlot = React.useCallback(
    (sha256: string, patch: Partial<SegmentSlot>) =>
      setSlots((current) =>
        current.map((slot) =>
          slot.segment.sha256 === sha256 ? { ...slot, ...patch } : slot,
        ),
      ),
    [],
  );

  const loadSegment = React.useCallback(
    async (segment: AgentTranscriptSegment) => {
      updateSlot(segment.sha256, { items: null, error: null });
      try {
        const frames = (await readAgentTranscriptSegment(
          manifest,
          segment.sha256,
        )) as ObserverEvent[];
        updateSlot(segment.sha256, {
          items: buildTranscriptState(frames.flatMap(unwrapObserverBatch))
            .items,
        });
      } catch (error) {
        updateSlot(segment.sha256, { error: errorText(error) });
      }
    },
    [manifest, updateSlot],
  );

  const loadEarlier = React.useCallback(async () => {
    let cursor = cursorRef.current;
    if (!cursor) return;
    setPaging(true);
    setPageError(null);
    try {
      let step = nextTranscriptStep(cursor);
      while (step?.kind === "page") {
        cursor = withPage(
          cursor,
          await readAgentTranscriptPage(manifest, step.sha256),
        );
        cursorRef.current = cursor;
        step = nextTranscriptStep(cursor);
      }
      if (!step) {
        setExhausted(true);
        return;
      }
      const { segment } = step;
      cursorRef.current = showSegment(cursor);
      setExhausted(nextTranscriptStep(cursorRef.current) === null);
      setSlots((current) => [
        ...current,
        { segment, items: null, error: null },
      ]);
      void loadSegment(segment);
    } catch (error) {
      setPageError(errorText(error));
    } finally {
      setPaging(false);
    }
  }, [loadSegment, manifest]);

  const started = React.useRef(false);
  React.useEffect(() => {
    if (started.current) return;
    started.current = true;
    void loadEarlier();
  }, [loadEarlier]);

  if (!parsed) {
    return (
      <p className="text-sm text-destructive">
        This transcript uses a format Buzz cannot read.
      </p>
    );
  }

  return (
    <div className="flex min-h-0 flex-col gap-3 overflow-y-auto">
      {pageError ? (
        <InlineError
          message={pageError}
          onRetry={() => void loadEarlier()}
          retryLabel="Retry loading earlier transcript"
        />
      ) : !exhausted ? (
        <Button
          className="self-center"
          disabled={paging}
          onClick={() => void loadEarlier()}
          size="sm"
          variant="outline"
        >
          {paging ? <Spinner aria-hidden className="h-3.5 w-3.5" /> : null}
          Load earlier
        </Button>
      ) : null}
      {slots.length === 0 && exhausted ? (
        <p className="text-sm text-muted-foreground">No transcript yet.</p>
      ) : null}
      {[...slots].reverse().map((slot) => (
        <section
          aria-label={`Turn at ${new Date(slot.segment.at * 1000).toLocaleString()}`}
          data-testid="agent-transcript-segment"
          key={slot.segment.sha256}
        >
          {slot.error ? (
            <InlineError
              message={`Could not load this turn: ${slot.error}`}
              onRetry={() => void loadSegment(slot.segment)}
              retryLabel="Retry loading this turn"
            />
          ) : (
            <AgentSessionTranscriptList
              agentAvatarUrl={agentAvatarUrl}
              agentName={agentName}
              agentPubkey={agentPubkey}
              emptyDescription="This turn has no messages."
              emptyState={slot.items ? "idle" : "loading"}
              items={slot.items ?? []}
            />
          )}
        </section>
      ))}
    </div>
  );
}

/** Dialog that pages through an agent's NIP-AF transcript, newest turn first. */
export function AgentTranscriptDialog({
  onOpenChange,
  open,
  ...viewer
}: ViewerProps & {
  onOpenChange: (open: boolean) => void;
  open: boolean;
}) {
  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="flex max-h-[85vh] max-w-3xl flex-col gap-4">
        <DialogHeader>
          <DialogTitle>Transcript</DialogTitle>
          <DialogDescription>
            What {viewer.agentName} read and wrote, newest turn last.
          </DialogDescription>
        </DialogHeader>
        {open ? <TranscriptViewer {...viewer} /> : null}
      </DialogContent>
    </Dialog>
  );
}
