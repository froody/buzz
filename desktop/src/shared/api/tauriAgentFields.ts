import type { RelayEvent } from "@/shared/api/types";
import { invokeTauri } from "./tauri";

/** A NIP-AF field the signed-in user can read, as returned by `read_agent_fields`. */
export type AgentField = {
  key: string;
  value: string;
  type: "text" | "transcript";
  visibility: "owner" | "community";
  createdAt: number;
};

/** Decode an agent's NIP-AF events into the fields the signed-in user can read. */
export async function readAgentFields(
  agentPubkey: string,
  events: RelayEvent[],
): Promise<AgentField[]> {
  return invokeTauri<AgentField[]>("read_agent_fields", {
    agentPubkey,
    events,
  });
}

/** One transcript segment listed in a NIP-AF transcript manifest. */
export type AgentTranscriptSegment = {
  sha256: string;
  size: number;
  turnId?: string;
  at: number;
};

/** A NIP-AF transcript manifest: the `transcript` field value or an `earlier` page. */
export type AgentTranscriptManifest = {
  v: number;
  segments: AgentTranscriptSegment[];
  earlier?: string | null;
  key?: string;
};

/** Fetch and decrypt one segment into its observer frames. `manifest` is the field value. */
export async function readAgentTranscriptSegment(
  manifest: string,
  sha256: string,
): Promise<unknown[]> {
  return invokeTauri<unknown[]>("read_agent_transcript_segment", {
    manifest,
    sha256,
  });
}

/** Fetch and decrypt an `earlier` page. `manifest` is the field value, which holds the key. */
export async function readAgentTranscriptPage(
  manifest: string,
  sha256: string,
): Promise<AgentTranscriptManifest> {
  return invokeTauri<AgentTranscriptManifest>("read_agent_transcript_page", {
    manifest,
    sha256,
  });
}
