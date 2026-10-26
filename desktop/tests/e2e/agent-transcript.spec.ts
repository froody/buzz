import { expect, type Page, test } from "@playwright/test";

import { waitForAnimations } from "../helpers/animations";
import { installMockBridge } from "../helpers/bridge";

async function waitForMockLiveSubscription(page: Page, channelName: string) {
  await expect
    .poll(() =>
      page.evaluate(
        (name) =>
          window.__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__?.({
            channelName: name,
          }) ?? false,
        channelName,
      ),
    )
    .toBe(true);
}

const sha = (c: string) => c.repeat(64);
const sessionId = "sess-transcript";

function turn(seq: number, prompt: string, reply: string) {
  const base = {
    agentIndex: 0,
    sessionId,
    timestamp: `2026-10-26T00:00:0${seq}Z`,
    turnId: `turn-${seq}`,
  };
  return [
    {
      ...base,
      seq: seq * 10,
      kind: "acp_write",
      payload: {
        method: "session/prompt",
        params: { sessionId, prompt: [{ type: "text", text: prompt }] },
      },
    },
    {
      ...base,
      seq: seq * 10 + 1,
      kind: "acp_read",
      payload: {
        method: "session/update",
        params: {
          sessionId,
          update: {
            sessionUpdate: "agent_message_chunk",
            content: { type: "text", text: reply },
          },
        },
      },
    },
  ];
}

const segment = (c: string, at: number) => ({ sha256: sha(c), size: 1, at });

test("transcript viewer pages newest first and isolates a failed turn", async ({
  page,
}) => {
  await installMockBridge(page, {
    agentTranscript: {
      manifest: JSON.stringify({
        v: 1,
        segments: [segment("c", 1793400002), segment("d", 1793400003)],
        earlier: sha("p"),
        key: "a2V5",
      }),
      blobs: {
        [sha("d")]: turn(3, "Ship the fix", "Newest turn reply"),
        [sha("p")]: {
          v: 1,
          segments: [segment("b", 1793400001)],
          earlier: null,
        },
        [sha("b")]: turn(1, "Start the task", "Oldest turn reply"),
      },
    },
  });
  await page.goto("/");

  await page.getByTestId("channel-general").click();
  await page.waitForFunction(() =>
    Boolean(
      (window as Window & { __BUZZ_E2E_INVOKE_MOCK_COMMAND__?: unknown })
        .__BUZZ_E2E_INVOKE_MOCK_COMMAND__,
    ),
  );
  const agentPubkey = await page.evaluate(async () => {
    const invoke = (
      window as Window & {
        __BUZZ_E2E_INVOKE_MOCK_COMMAND__?: (
          command: string,
          payload?: Record<string, unknown>,
        ) => Promise<{ agent?: { pubkey: string }; id?: string }>;
      }
    ).__BUZZ_E2E_INVOKE_MOCK_COMMAND__;
    if (!invoke) throw new Error("Mock bridge is not installed.");
    const persona = await invoke("create_persona", {
      input: { displayName: "Transcript Bot", systemPrompt: "Help." },
    });
    const created = await invoke("create_managed_agent", {
      input: {
        name: "Transcript Bot",
        personaId: persona.id,
        spawnAfterCreate: true,
        systemPrompt: "Help.",
      },
    });
    const pubkey = created.agent?.pubkey;
    if (!pubkey) throw new Error("Mock agent creation returned no pubkey.");
    return pubkey;
  });

  await waitForMockLiveSubscription(page, "general");
  await page.evaluate((pubkey) => {
    const emit = (
      window as Window & {
        __BUZZ_E2E_EMIT_MOCK_MESSAGE__?: (input: {
          channelName: string;
          content: string;
          pubkey: string;
        }) => unknown;
      }
    ).__BUZZ_E2E_EMIT_MOCK_MESSAGE__;
    if (!emit) throw new Error("Mock message emitter is unavailable.");
    emit({ channelName: "general", content: "Transcript check-in", pubkey });
  }, agentPubkey);
  await page
    .getByTestId("message-row")
    .filter({ hasText: "Transcript check-in" })
    .locator("button")
    .first()
    .click();

  await page.getByTestId("user-profile-agent-field-transcript-view").click();
  const dialog = page.getByRole("dialog", { name: "Transcript" });
  await expect(dialog.getByText("Newest turn reply")).toBeVisible();

  await dialog.getByRole("button", { name: "Load earlier" }).click();
  await expect(
    dialog.getByRole("button", { name: "Retry loading this turn" }),
  ).toBeVisible();
  await expect(dialog.getByText("Newest turn reply")).toBeVisible();

  await dialog.getByRole("button", { name: "Load earlier" }).click();
  await expect(dialog.getByText("Oldest turn reply")).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Load earlier" }),
  ).toHaveCount(0);

  await waitForAnimations(page);
  await dialog.screenshot({
    path: "test-results/agent-transcript/transcript-viewer.png",
  });
});
