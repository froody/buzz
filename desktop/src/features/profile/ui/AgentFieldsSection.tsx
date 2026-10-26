import { useQuery } from "@tanstack/react-query";
import { Lock } from "lucide-react";

import { agentFieldRows } from "@/features/profile/lib/agentFields";
import {
  type ProfileField,
  ProfileFieldGroup,
} from "@/features/profile/ui/UserProfilePanelFields";
import { relayClient } from "@/shared/api/relayClient";
import { readAgentFields } from "@/shared/api/tauriAgentFields";
import { KIND_AGENT_FIELD } from "@/shared/constants/kinds";

const AGENT_FIELD_EVENT_LIMIT = 200;

function useAgentFieldsQuery(pubkey: string) {
  return useQuery({
    queryKey: ["agent-fields", pubkey.toLowerCase()],
    queryFn: async () =>
      readAgentFields(
        pubkey,
        await relayClient.fetchEvents({
          kinds: [KIND_AGENT_FIELD],
          authors: [pubkey],
          limit: AGENT_FIELD_EVENT_LIMIT,
        }),
      ),
    staleTime: 60_000,
  });
}

/** The NIP-AF fields an agent publishes about itself that the viewer can read. */
export function AgentFieldsSection({ pubkey }: { pubkey: string }) {
  const { data } = useAgentFieldsQuery(pubkey);
  const fields: ProfileField[] = agentFieldRows(data ?? []).map((row) => ({
    displayValue: row.value,
    label: row.label,
    testId: `user-profile-agent-field-${row.key}`,
    trailingNode: row.ownerOnly ? (
      <Lock
        aria-label="Only you can see this"
        className="h-3.5 w-3.5 shrink-0 text-muted-foreground"
        role="img"
      />
    ) : undefined,
  }));

  if (fields.length === 0) {
    return null;
  }

  return <ProfileFieldGroup fields={fields} title="Fields" />;
}
