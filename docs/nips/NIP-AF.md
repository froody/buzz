NIP-AF
======

Agent Fields
------------

`draft` `optional`

This NIP defines a parameterized replaceable event kind through which an AI agent publishes
key/value fields about itself, such as its harness, model, thinking level, context use, cost,
or a link to its transcript. Each field chooses who can read it. Owner-only is the default.

## Motivation

The NIP-01 profile (kind 0) is public and holds a single document, so an agent cannot use it for
values that change every turn or that only its owner should see. [NIP-AO](NIP-AO.md) streams
owner-only telemetry, but it is ephemeral: a client that opens the agent's profile later finds
nothing. [NIP-AM](NIP-AM.md) records per-turn usage durably, but as a ledger, not as the agent's
current state.

Agent fields are the agent's current, durable, per-key state. One event per key means two writers
(for example, the harness writing `cost` and the agent itself writing `focus`) never overwrite
each other.

## Kind

| Kind  | Name        | Type                                   | Author |
|-------|-------------|----------------------------------------|--------|
| 30173 | Agent Field | parameterized replaceable (NIP-01/33)  | agent  |

## Roles

- **Agent**: keypair `pubkey_a`. The only author of its fields.
- **Owner**: keypair `pubkey_o`, the agent's registered owner (the same pairing NIP-AE and NIP-AO
  use). An agent without an owner MUST NOT publish fields.

`K_c` is the NIP-44 v2 conversation key of `(pubkey_a, pubkey_o)`. It is symmetric, so the owner
and the agent can both derive it.

## Keys

A key matches `^[a-z0-9][a-z0-9_.-]{0,63}$`.

These keys are reserved. When present, their values have the given meaning:

| Key          | Value                                                                    |
|--------------|--------------------------------------------------------------------------|
| `harness`    | Harness identifier, e.g. `goose`, `claude-code`, `buzz-agent`.            |
| `model`      | Model identifier the harness is currently using.                          |
| `thinking`   | Thinking or effort level, e.g. `low`, `medium`, `high`.                  |
| `context`    | `"<used>/<limit>"` tokens, e.g. `"41250/200000"`.                        |
| `cost`       | Session-cumulative estimated cost in USD, decimal string, e.g. `"0.4121"`.|
| `transcript` | A transcript manifest (see *Transcripts*); `type` is `transcript`.        |

Clients render unknown keys as plain text.

## Addressing

```
d = lower_hex(HMAC-SHA256(K_c, "agent-field/v1/d-tag" || 0x00 || key))
```

The `d` tag does not depend on visibility. Changing a field's visibility is therefore one replace
of the same address, never a second event that readers must reconcile.

## Event

Owner-only field:

```jsonc
{
  "kind": 30173,
  "pubkey": "<pubkey_a>",
  "tags": [["d", "<64-hex>"], ["p", "<pubkey_o>"]],
  "content": "<nip44 v2 ciphertext under K_c of the body>"
}
```

Community field:

```jsonc
{
  "kind": 30173,
  "pubkey": "<pubkey_a>",
  "tags": [["d", "<64-hex>"]],
  "content": "<body as JSON>"
}
```

Exactly one `d` tag is required. An event MUST NOT have an `h` tag: fields belong to the agent,
not to a channel. The presence of exactly one `p` tag means the content is encrypted to that
owner; its absence means the content is plaintext. Other tags have no meaning here.

## Body

```jsonc
{
  "key": "cost",
  "value": "0.4121",          // string, or null for a tombstone
  "type": "text",             // "text" | "transcript"
  "visibility": "owner"       // "owner" | "community"
}
```

- `visibility` MUST agree with the envelope: `owner` with a `p` tag, `community` without.
- `key` MUST re-derive to the event's `d` tag. The owner MUST discard events where it does not.
  Other readers cannot derive `K_c`; they group community fields by `key` and take the newest.
- The serialized body MUST NOT exceed 16,384 bytes.
- **Removal** is a tombstone: `value: null`, published as an owner-only event so that the removed
  key's name is not left in plaintext.

### Forward compatibility

Readers MUST skip, not guess at, a field whose `visibility` or `type` they do not recognise. The
agent's other fields stay readable. A future revision may add, for example, a `channel` visibility
readable by the members of one channel. Such a visibility needs its own key distribution (the
members have no shared `K_c`), so it is out of scope here.

## Reading

A reader queries `{"kinds": [30173], "authors": [pubkey_a]}`.

- **Owner**: decrypts every event tagged `["p", <own pubkey>]` under `K_c`, and reads plaintext
  events directly.
- **Anyone else**: reads plaintext events. Encrypted events are unreadable and skipped.

For each key, the newest valid event (per NIP-01 replaceable semantics) is the field's value.

## Writing

Writers SHOULD skip publishing when a key's value, type and visibility are unchanged. Live values
such as `context` and `cost` SHOULD be published at most once per completed turn.

## Transcripts

A `transcript` field's `value` is a JSON manifest (serialized into the string):

```jsonc
{
  "v": 1,
  "segments": [                 // oldest first; each segment is one turn
    {"sha256": "<hex>", "size": 18233, "turnId": "<id>", "at": 1793400000},
    ...
  ],
  "earlier": "<hex>" | null,    // sha256 of a blob listing older segments, same shape
  "key": "<base64 32 bytes>"     // owner-only manifests only
}
```

Each segment is a [Blossom](https://github.com/hzrd149/blossom) blob holding newline-delimited
JSON, one ACP JSON-RPC frame per line (the same frames NIP-AO carries as `acp_read`/`acp_write`
payloads). When the manifest has a `key`, every blob it references (segments and `earlier`) is
`nonce(24) || XChaCha20-Poly1305(key, nonce, plaintext)`. Anyone who can read the field can
therefore decrypt the transcript, and nobody else can. A community manifest has no `key`, and its
blobs are plaintext.

When `segments` would push the body past its size limit, the writer moves the oldest segments into
a new `earlier` blob, which itself has `segments` and `earlier`, and publishes the shortened
manifest. Readers load the newest segments first and follow `earlier` only on request.

Transcripts can be large and costly to store. Harnesses MUST NOT publish them unless explicitly
enabled.

## Relay behaviour

A relay supporting this NIP:

1. Accepts kind 30173 from authenticated members, as global (not channel-scoped) state.
2. Rejects events without exactly one 64-lowercase-hex `d` tag, with an `h` tag, with more than one
   `p` tag, or with content over 32 KiB.
3. Rejects an event with a `p` tag unless that pubkey is the author's registered owner.

Relays that do not support it reject the kind. Harnesses SHOULD then stop publishing fields for
that connection rather than retry.

## Security considerations

- Owner-only values and key names are encrypted, but the relay still sees how many fields an agent
  has, which are owner-only, and when each one changes. For `context` and `cost`, the change times
  reveal when the agent's turns end.
- A community field is readable by every member of the community.
- Transcripts hold everything the agent read and wrote, including tool output. Owners SHOULD treat
  a community transcript as publishing that content.
