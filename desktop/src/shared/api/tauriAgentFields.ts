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
