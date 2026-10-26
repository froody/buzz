import * as React from "react";

import { normalizePubkey } from "@/shared/lib/pubkey";
import {
  type ActiveChannelTurnSummary,
  getActiveTurnsByChannel,
  getActiveTurnsForAgent,
  subscribeActiveAgentTurns,
} from "./activeAgentTurnsStore";

/**
 * Unified "agent is working" signal.
 *
 * Every surface that shows a working affordance (sidebar channel badges,
 * profile badges, agent rows, composer activity bar, activity panel header,
 * future thread ingresses) should read from this module instead of picking
 * one of the underlying pipes. The rule is:
 *
 *   1. Observer-derived active turns (kind 24200 → activeAgentTurnsStore)
 *      are the primary signal — they carry channel scope and a start anchor.
 *   2. Bot typing indicators (kind 20002, mirrored into this module by the
 *      channel typing hooks) are the fallback for agents whose observer
 *      stream is absent for that scope (e.g. remote harness without relay
 *      observer, or frames not yet arrived).
 *
 * Scope rule: with a channelId, "working" means working in that channel;
 * without one, "working" means any active work in any channel (the
 * all-channels rule the activity panel uses).
 */

export type AgentWorkingSource = "observer" | "typing" | "none";

/** Coarse agent phase carried by bot typing indicators (`["phase", …]`). */
export type AgentWorkingPhase = "thinking" | "tool" | "writing";

const AGENT_WORKING_PHASES: readonly string[] = ["thinking", "tool", "writing"];

/** Phase from a typing event's tags; absent or unknown values yield null. */
export function parseTypingPhase(
  tags: readonly (readonly string[])[],
): AgentWorkingPhase | null {
  const value = tags.find((tag) => tag[0] === "phase")?.[1];
  return value !== undefined && AGENT_WORKING_PHASES.includes(value)
    ? (value as AgentWorkingPhase)
    : null;
}

export type AgentWorkingChannel = {
  channelId: string;
  /** Desktop-clock anchor for elapsed displays (turn start / first typing). */
  anchorAt: number;
  source: Exclude<AgentWorkingSource, "none">;
  /** Latest typing-reported phase for this channel, if any. */
  phase: AgentWorkingPhase | null;
};

export type AgentWorkingState = {
  working: boolean;
  /** Strongest signal backing `working` for the requested scope. */
  source: AgentWorkingSource;
  /** Every channel the agent is working in (unscoped), observer-primary. */
  channels: AgentWorkingChannel[];
  /** Phase of the most recently started working channel in scope. */
  phase: AgentWorkingPhase | null;
};

export type WorkingChannelSummary = ActiveChannelTurnSummary & {
  source: Exclude<AgentWorkingSource, "none">;
};

const IDLE_STATE: AgentWorkingState = {
  working: false,
  source: "none",
  channels: [],
  phase: null,
};

// ── Typing registry (fallback input) ────────────────────────────────────────
// channelId → (normalized agent pubkey → first-seen ms + phase). Fed by
// reportChannelBotTyping from the channel typing hooks; entries follow the
// typing TTL because the hooks re-report whenever their entries change.
type TypingRecord = { since: number; phase: AgentWorkingPhase | null };
const typingByChannel = new Map<string, Map<string, TypingRecord>>();

const listeners = new Set<() => void>();
let unsubscribeTurns: (() => void) | null = null;

// Reference-stable snapshots for useSyncExternalStore. React reads a snapshot
// before it subscribes, so these must be stable even with no listeners yet.
const stateCache = new Map<string, AgentWorkingState>();
let channelsCache: WorkingChannelSummary[] | null = null;
const channelPubkeysCache = new Map<string, string[]>();

function invalidateCaches() {
  stateCache.clear();
  channelsCache = null;
  channelPubkeysCache.clear();
}

function notify() {
  invalidateCaches();
  for (const listener of listeners) {
    listener();
  }
}

export function subscribeAgentWorkingSignal(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1) {
    invalidateCaches();
    unsubscribeTurns = subscribeActiveAgentTurns(notify);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      unsubscribeTurns?.();
      unsubscribeTurns = null;
    }
  };
}

/**
 * Mirror the current bot typing pubkeys for a channel into the signal.
 * Call with the full current set (empty array clears the channel) and the
 * phase of each pubkey that reported one. First-seen timestamps are preserved
 * across re-reports so elapsed anchors stay stable.
 */
export function reportChannelBotTyping(
  channelId: string,
  pubkeys: readonly string[],
  phases: Readonly<Record<string, AgentWorkingPhase>> = {},
) {
  const current = typingByChannel.get(channelId);
  const next = new Map<string, TypingRecord>();
  const now = Date.now();
  for (const pubkey of pubkeys) {
    const key = normalizePubkey(pubkey);
    next.set(key, {
      since: current?.get(key)?.since ?? now,
      phase: phases[pubkey] ?? null,
    });
  }

  const unchanged =
    (current?.size ?? 0) === next.size &&
    [...next].every(
      ([key, record]) => current?.get(key)?.phase === record.phase,
    );
  if (unchanged) {
    return;
  }

  if (next.size === 0) {
    typingByChannel.delete(channelId);
  } else {
    typingByChannel.set(channelId, next);
  }
  notify();
}

function computeAgentWorkingState(
  agentPubkey: string,
  channelId: string | null,
): AgentWorkingState {
  const key = normalizePubkey(agentPubkey);
  const turns = getActiveTurnsForAgent(key);

  const channels: AgentWorkingChannel[] = turns.map((turn) => ({
    channelId: turn.channelId,
    anchorAt: turn.anchorAt,
    source: "observer" as const,
    phase: typingByChannel.get(turn.channelId)?.get(key)?.phase ?? null,
  }));
  const observerChannelIds = new Set(turns.map((turn) => turn.channelId));

  for (const [typingChannelId, entries] of typingByChannel) {
    if (observerChannelIds.has(typingChannelId)) {
      continue;
    }
    const record = entries.get(key);
    if (record) {
      channels.push({
        channelId: typingChannelId,
        anchorAt: record.since,
        source: "typing",
        phase: record.phase,
      });
    }
  }

  if (channels.length === 0) {
    return IDLE_STATE;
  }

  channels.sort((a, b) => a.channelId.localeCompare(b.channelId));

  const scoped =
    channelId === null
      ? channels
      : channels.filter((channel) => channel.channelId === channelId);
  const source: AgentWorkingSource = scoped.some(
    (channel) => channel.source === "observer",
  )
    ? "observer"
    : scoped.length > 0
      ? "typing"
      : "none";

  let latest: AgentWorkingChannel | null = null;
  for (const channel of scoped) {
    if (!latest || channel.anchorAt > latest.anchorAt) {
      latest = channel;
    }
  }

  return {
    working: source !== "none",
    source,
    channels,
    phase: latest?.phase ?? null,
  };
}

/**
 * Working state for one agent, optionally scoped to a channel. Returns a
 * reference-stable snapshot while subscribed (useSyncExternalStore-safe).
 */
export function getAgentWorkingState(
  agentPubkey: string | null | undefined,
  channelId: string | null = null,
): AgentWorkingState {
  if (!agentPubkey) {
    return IDLE_STATE;
  }
  const cacheKey = `${normalizePubkey(agentPubkey)}|${channelId ?? ""}`;
  const cached = stateCache.get(cacheKey);
  if (cached) {
    return cached;
  }
  const state = computeAgentWorkingState(agentPubkey, channelId);
  stateCache.set(cacheKey, state);
  return state;
}

/**
 * All channels with agent work in progress, aggregated across agents and
 * merged observer-primary: typing-only agents fold into an existing observer
 * summary; channels with only typing get a typing-sourced summary anchored to
 * first-seen typing.
 */
export function getWorkingChannels(): WorkingChannelSummary[] {
  if (channelsCache) {
    return channelsCache;
  }

  const byChannel = new Map<string, WorkingChannelSummary>();
  for (const summary of getActiveTurnsByChannel()) {
    byChannel.set(summary.channelId, { ...summary, source: "observer" });
  }

  for (const [channelId, entries] of typingByChannel) {
    const existing = byChannel.get(channelId);
    if (existing) {
      const known = new Set(
        existing.agentPubkeys.map((pubkey) => normalizePubkey(pubkey)),
      );
      const merged = [...existing.agentPubkeys];
      for (const pubkey of entries.keys()) {
        if (!known.has(pubkey)) {
          merged.push(pubkey);
        }
      }
      if (merged.length !== existing.agentPubkeys.length) {
        byChannel.set(channelId, {
          ...existing,
          agentPubkeys: merged,
          agentCount: merged.length,
        });
      }
      continue;
    }

    let anchorAt = Number.POSITIVE_INFINITY;
    for (const { since } of entries.values()) {
      if (since < anchorAt) {
        anchorAt = since;
      }
    }
    byChannel.set(channelId, {
      channelId,
      anchorAt,
      agentCount: entries.size,
      agentPubkeys: [...entries.keys()],
      source: "typing",
    });
  }

  const result = [...byChannel.values()].sort((a, b) =>
    a.channelId.localeCompare(b.channelId),
  );
  channelsCache = result;
  return result;
}

const EMPTY_PUBKEYS: string[] = [];

/**
 * Normalized pubkeys of every agent working in the given channel
 * (observer turns ∪ typing fallback). Stable while subscribed.
 */
export function getWorkingAgentPubkeysForChannel(
  channelId: string | null | undefined,
): string[] {
  if (!channelId) {
    return EMPTY_PUBKEYS;
  }
  const cached = channelPubkeysCache.get(channelId);
  if (cached) {
    return cached;
  }
  const merged = new Set<string>();
  for (const summary of getActiveTurnsByChannel()) {
    if (summary.channelId !== channelId) {
      continue;
    }
    for (const pubkey of summary.agentPubkeys) {
      merged.add(normalizePubkey(pubkey));
    }
  }
  const typing = typingByChannel.get(channelId);
  if (typing) {
    for (const pubkey of typing.keys()) {
      merged.add(pubkey);
    }
  }
  const result = merged.size === 0 ? EMPTY_PUBKEYS : [...merged].sort();
  channelPubkeysCache.set(channelId, result);
  return result;
}

// ── Hooks ────────────────────────────────────────────────────────────────────

/** Working state for one agent, optionally scoped to a channel. */
export function useAgentWorking(
  agentPubkey: string | null | undefined,
  channelId: string | null = null,
): AgentWorkingState {
  return React.useSyncExternalStore(subscribeAgentWorkingSignal, () =>
    getAgentWorkingState(agentPubkey, channelId),
  );
}

/** All channels with agent work in progress, across agents. */
export function useWorkingChannels(): WorkingChannelSummary[] {
  return React.useSyncExternalStore(
    subscribeAgentWorkingSignal,
    getWorkingChannels,
  );
}

/** Normalized pubkeys of agents working in a channel. */
export function useChannelWorkingAgentPubkeys(
  channelId: string | null | undefined,
): string[] {
  return React.useSyncExternalStore(subscribeAgentWorkingSignal, () =>
    getWorkingAgentPubkeysForChannel(channelId),
  );
}

/** Community-switch reset (see resetCommunityState in useCommunityInit). */
export function resetAgentWorkingSignal() {
  typingByChannel.clear();
  invalidateCaches();
  for (const listener of listeners) {
    listener();
  }
}
