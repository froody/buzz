import type { AgentField } from "@/shared/api/tauriAgentFields";

const RESERVED_LABELS: Record<string, string> = {
  harness: "Harness",
  model: "Model",
  thinking: "Thinking",
  context: "Context",
  cost: "Cost",
  transcript: "Transcript",
};
const RESERVED_ORDER = Object.keys(RESERVED_LABELS);

function compactTokens(tokens: number): string {
  if (tokens >= 1_000_000) return `${Number((tokens / 1_000_000).toFixed(1))}M`;
  if (tokens >= 1_000) return `${Math.round(tokens / 1_000)}k`;
  return `${tokens}`;
}

function formatValue(field: AgentField): string {
  if (field.type === "transcript") return "Transcript available";
  if (field.key === "context") {
    const match = /^(\d+)\/(\d+)$/.exec(field.value.trim());
    if (match) {
      return `${compactTokens(Number(match[1]))} / ${compactTokens(Number(match[2]))}`;
    }
  }
  if (field.key === "cost") {
    const usd = Number(field.value);
    if (field.value.trim() !== "" && Number.isFinite(usd)) {
      return `$${usd.toFixed(2)}`;
    }
  }
  return field.value;
}

/** Display rows for agent fields: reserved keys first with friendly labels and values. */
export function agentFieldRows(fields: AgentField[]) {
  const rank = (key: string) => {
    const index = RESERVED_ORDER.indexOf(key);
    return index === -1 ? RESERVED_ORDER.length : index;
  };
  return [...fields]
    .sort((a, b) => rank(a.key) - rank(b.key) || a.key.localeCompare(b.key))
    .map((field) => ({
      key: field.key,
      label: RESERVED_LABELS[field.key] ?? field.key,
      value: formatValue(field),
      ownerOnly: field.visibility === "owner",
      transcript: field.type === "transcript" ? field.value : null,
    }));
}
