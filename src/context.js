// What Jev gets to see besides the tool call itself: the user's recent words, the agent's stated intent,
// the last few decisions, and anything flagged as untrusted earlier in the session. Sources, in order:
// the session store (fed by every host's prompt/tool hooks), a Claude-style JSONL transcript when the
// host hands us one, and whatever the adapter already knows (Cursor's agent_message, pi's session entries).
import { closeSync, openSync, readSync, statSync } from "node:fs";
import { readSession } from "./session.js";

const TAIL_BYTES = 256 * 1024;
const MAX_TEXT = 700;

export function buildContext({ sessionId, transcriptPath, intent, messages, currentCallID } = {}) {
  const s = readSession(sessionId);
  let prompts = s.prompts.map((p) => p.text);
  let answers = [];
  let intents = s.intents.map((i) => i.text);
  if (messages) {  // adapter-supplied [{role, text}] (pi, OpenCode, ACP)
    prompts = [...prompts, ...messages.filter((m) => m.role === "user" && m?.type !== "answers").map((m) => m.text)];
    answers = [...answers, ...messages.filter((m) => m.role === "user" && m?.type === "answers").map((m) => m.text)];
    intents = [...intents, ...messages.filter((m) => m.role === "assistant").map((m) => m.text)];
  } else if (transcriptPath) {
    const t = readTranscript(transcriptPath);
    prompts = [...prompts, ...t.user];
    intents = [...intents, ...t.assistant];
  }
  if (intent) intents.push(intent);

  // Exclude the call being judged BEFORE slicing, so the window stays full.
  const calls = s.calls
    .filter((c) => !currentCallID || c.callID !== currentCallID)
    .map((c) => {
      const tags = [c.level && c.level !== "allow" ? c.level : null, c.outcome && c.outcome !== "ran" ? c.outcome : null]
        .filter(Boolean);
      return `${c.tool} ${c.preview}${tags.length ? ` [${tags.join(", ")}]` : ""}`;
    })
    // legacy rows have no callID: collapse consecutive identical lines
    .filter((line, i, arr) => i === 0 || line !== arr[i - 1])
    .slice(-6);

  const ctx = {
    user_recent_messages: dedupeLast(prompts).slice(-3).map(clip),
    user_recent_answers: answers,
    assistant_intent: clip(intents.at(-1) ?? ""),
    recent_tool_calls: calls,
    flagged_untrusted_content: s.flags.slice(-5).map((f) => `${f.kind} from ${f.source ?? f.tool ?? "unknown"}${f.p ? ` (p=${f.p})` : ""}${f.excerpt ? `: "${f.excerpt}"` : ""}`),
  };
  for (const k of Object.keys(ctx)) if (!ctx[k] || ctx[k].length === 0) delete ctx[k];
  return Object.keys(ctx).length ? ctx : undefined;
}

/** Last user texts and assistant texts from a Claude Code style JSONL transcript. Tool results are not user words. */
export function readTranscript(path) {
  const out = { user: [], assistant: [] };
  let raw;
  try {
    const size = statSync(path).size;
    const fd = openSync(path, "r");
    const len = Math.min(size, TAIL_BYTES);
    const buf = Buffer.alloc(len);
    readSync(fd, buf, 0, len, size - len);
    closeSync(fd);
    raw = buf.toString("utf8");
  } catch { return out; }
  for (const line of raw.split("\n").slice(1)) {  // first line may be a partial record
    let rec;
    try { rec = JSON.parse(line); } catch { continue; }
    const role = rec.message?.role ?? rec.type ?? rec.role;
    const content = rec.message?.content ?? rec.content;
    const text = textOf(content);
    if (!text) continue;
    if (role === "user") out.user.push(text);
    else if (role === "assistant") out.assistant.push(text);
  }
  return out;
}

function textOf(content) {
  if (typeof content === "string") return content.trim();
  if (!Array.isArray(content)) return "";
  return content.filter((b) => b?.type === "text" && typeof b.text === "string").map((b) => b.text.trim()).filter(Boolean).join("\n");
}

//const clip = (s) => (s.length > MAX_TEXT ? s.slice(0, MAX_TEXT) + "…" : s);
const clip = (s) => s.length > MAX_TEXT
  ? s.slice(0, Math.ceil(MAX_TEXT * 0.6)) + " …[cut]… " + s.slice(-Math.floor(MAX_TEXT * 0.4))
  : s;
// Keep the LAST occurrence, so a repeated message keeps its most recent position.
const dedupeLast = (arr) => arr.filter((x, i) => x && arr.lastIndexOf(x) === i);

/** Text of every user/assistant message from pi's session entries or OpenCode's session.messages(). */
export function messagesFrom(entries) {
  const out = [];
  for (const e of entries ?? []) {
    const m = e.message ?? e;                              // pi: {type:"message", message:{role, content}}
    const role = m.role ?? e.info?.role;                   // opencode: {info:{role}, parts:[{type,text}]}
    if (role !== "user" && role !== "assistant") continue;
    const text = textOf(m.content) || textOf(e.parts);
    if (text) out.push({ role, text });
    if (role === "assistant") {
      for (const p of e.parts ?? []) {
        if (p.type !== "tool" || p.tool !== "question") continue
        
        const a = p.state?.metadata?.answers
        if (!a?.length) continue
        const formatted = a.map((x, i) => {
          const q = p.state?.input?.questions?.[i]?.question ?? `Q${i + 1}`
          return `"${q}": "${x.join(", ")}"`
        }).join(" ")
        out.push({ role: "user", type: "answers", text: `${formatted}` })
      }
    }
  }
  return out.slice(-12);
}
