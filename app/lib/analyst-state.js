/* The analyst's conversation, shared.
 *
 * Plain isolate module: one transcript for the whole isolate, which is
 * the right shape for an instrument — everyone looking at this host
 * sees the same analysis, and a question asked from one tab is
 * answered in all of them. Module state also survives navigating to
 * the graph and back, where a page-local signal would not.
 */
import { createSignal } from "yeetkit";

/** [{ role: "user" | "assistant", text, tools: [{ name, args, ms }], at }] */
export const [turns, setTurns] = createSignal([]);
export const [thinking, setThinking] = createSignal(false);
export const [aiError, setAiError] = createSignal("");

export function appendTurn(turn) {
  setTurns((t) => [...t, turn]);
}

/** Mutate the last assistant turn in place (streaming). */
export function patchLast(fn) {
  setTurns((t) => {
    if (!t.length) return t;
    const last = { ...t[t.length - 1] };
    fn(last);
    return [...t.slice(0, -1), last];
  });
}

export function resetConversation() {
  setTurns([]);
  setAiError("");
}
