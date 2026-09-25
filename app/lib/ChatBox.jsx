"use client";

/* The question box. An island, because typing must not take a round
 * trip: the text lives in the browser until Enter, then one call goes
 * to the isolate and the answer streams back into the shared transcript
 * the page renders. */
import { createSignal } from "solid-js";

import { ask, cancel } from "@/lib/analyst.js";

const SUGGESTIONS = [
  "What changed since the last scan?",
  "Which network-facing process has the worst unpatched CVE?",
  "Trace execs for 8 seconds — what is this box doing right now?",
  "What is yeetd connecting to right now?",
];

export default function ChatBox(props) {
  const [text, setText] = createSignal("");
  const [error, setError] = createSignal("");
  let box;

  const send = async (q = text()) => {
    const question = q.trim();
    if (!question || props.thinking) return;
    setText("");
    setError("");
    const r = await ask(question);
    if (!r?.ok && r?.error) setError(r.error);
    box?.focus();
  };

  return (
    <div class="space-y-2">
      <div class="flex flex-wrap gap-2">
        {SUGGESTIONS.map((s) => (
          <button class="rounded-full border border-border px-3 py-1 text-xs text-muted hover:bg-bg hover:text-fg disabled:opacity-50" disabled={props.thinking} onClick={() => send(s)}>
            {s}
          </button>
        ))}
      </div>
      <div class="flex items-end gap-2">
        <textarea
          ref={box}
          rows="2"
          class="min-h-[2.75rem] flex-1 resize-y rounded-lg border border-border bg-bg px-3 py-2 text-fg placeholder:text-faint focus:border-accent focus:outline-none"
          placeholder={props.thinking ? "Answering…" : "Ask about this host — it can read the inventory, check advisories, diff the last scan, and trace live execs and connections."}
          value={text()}
          disabled={props.thinking}
          onInput={(e) => setText(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
        />
        {props.thinking ? (
          <button class="btn-secondary" onClick={() => cancel()}>
            Stop
          </button>
        ) : (
          <button class="btn" disabled={!text().trim()} onClick={() => send()}>
            Ask
          </button>
        )}
      </div>
      {error() && <div class="text-xs text-high">{error()}</div>}
    </div>
  );
}
