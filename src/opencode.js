// OpenCode plugin. `jev-guard install opencode` drops a one-line shim into ~/.config/opencode/plugins/ that re-exports this.
// tool.execute.before throws to block; permission.ask (only fires for tools you set to "ask" in opencode.json)
// lets jev-guard auto-approve the safe calls and keep the prompt for the risky ones; tool.execute.after flags results.
import { assessAction, scanContent, preview, excerpt, INSTRUCTION_FILE } from "./guard.js";
import { scanInstructionsCached } from "./skills.js";
import { buildContext, messagesFrom } from "./context.js";
import { readSession, remember } from "./session.js";

const INSTANCE = Math.random().toString(36).slice(2, 6);
console.error("[jev-guard init]", INSTANCE, process.pid);

export const JevGuard = async ({ client, directory }) => {
  const toast = (message, variant = "warning") =>
    client?.tui?.showToast?.({ body: { title: "jev-guard", message, variant, duration: 8000 } }).catch(() => {});
  const failOpen = (err) => {
    toast(err.message, "error");
    if (process.env.JEV_GUARD_FAIL_CLOSED) throw new Error(`jev-guard unavailable: ${err.message}`);
    return null;
  };

  // The session's messages, via the SDK; empty when the server can't be reached.
  const context = async (sessionID, currentCallID) => {
    const res = await client?.session?.messages?.({ path: { id: sessionID } }).catch(() => null);
    return buildContext({ sessionId: sessionID, messages: messagesFrom(res?.data ?? []), currentCallID:currentCallID });
  };

  return {
    "tool.execute.before": async (input, output) => {
     
      const ctx = await context(input.sessionID, input.callID);
      
      console.error("=== jev-guard opencode.js before execute ===", INSTANCE, Date.now()) 
      console.error(" > input ", input ? input : "missing")
      console.error(" > output ", output ? output : "missing")
      console.error(" > directory ", directory ? directory : "missing")
      console.error(" > context ", ctx ? ctx : "missing")
      console.error("===  ===")
      
      if(true) return;

      // Judge the real call when we have it; otherwise fall back to the permission descriptor.
      const r = await assessAction({ tool: input.tool, input: output.args, cwd: directory, agent: "opencode", context: ctx}).catch(failOpen);
      console.error("=== jev-guard opencode.js before execute result ", INSTANCE, Date.now(), r) 
        
      if(r){
        //console.error("=== jev-guard opencode.js before execute result ===", r)      
        toast(`${r.message} ${input.tool} ${r.level}`);
        
        remember(input.sessionID, "calls", {callID: input.callID, tool: input.tool, preview: preview(output.args, 100), level: r.level });
      }
      if (!r || r.level === "allow") return;
      if (r.level === "deny") throw new Error(r.message);

      if(r){
        toast(`${r.message} (set permission.${input.tool} to "ask" in opencode.json to get a real prompt)`);
        //console.error("=== jev-guard opencode.js before execute  ===", `(set permission.${input.tool} to "ask" in opencode.json to get a real prompt)`) 
      }      
    },

    "permission.ask": async (input, output) => {      
      const ctx = await context(input.sessionID, input.callID);
      console.error("=== jev-guard opencode.js permission ask ===", Date.now())
      console.error(" > input ", input ? input : "missing")      
      console.error(" > output ", output ? output : "missing")
      console.error(" > directory ", directory ? directory : "missing")
      console.error(" > context ", ctx ? ctx : "missing")
      console.error("===  ===")
      
      const args = { ...(input.metadata ?? {}), pattern: input.pattern, title: input.title };
      
      // Judge the real call when we have it; otherwise fall back to the permission descriptor.
      const r = await assessAction({ tool: input.type, input: args, cwd: directory, agent: "opencode", context: ctx}).catch(failOpen);
      console.error("=== jev-guard opencode.js permission ask result", Date.now(), r)
      
      if (!r) return;
      output.status = r.level;  // allow → no prompt, ask → prompt, deny → refused
      if (r?.message) output.message = r.message; // instruction why refused

      if (r.level !== "allow") toast(r.message);
    },

    "tool.execute.after": async (input, output) => {
      //console.error("=== jev-guard opencode.js after execute ===", input, output, directory)
      if(true) return;

      const source = input.args?.url ?? input.args?.filePath ?? input.args?.path;
      const instructions = /^skill$/i.test(input.tool ?? "") || (source && INSTRUCTION_FILE.test(source));  // skill passes {name}, no path
      const r = await (instructions
        ? scanInstructionsCached({ text: output.output, source: source ?? input.args?.name ?? input.tool })
        : scanContent({ text: output.output, tool: input.tool, source: preview(input.args, 120), task: readSession(input.sessionID).prompts.at(-1)?.text })
      ).catch(() => null);
      if (r?.flagged) remember(input.sessionID, "flags", { callID: input.callID, kind: r.kind, source, tool: input.tool, p: +r.p.toFixed(2), excerpt: excerpt(output.output), reported: true });
      if (!r?.flagged) return;
      toast(r.message);
      output.output = `[${r.message}]\n\n${output.output}`;
    },
  };
};

export default JevGuard;

// ponytail: both named and default export. Kilo's v1 plugin contract wants `default`; OpenCode's older loader
// iterates every export as a plugin function, so the named `JevGuard` is kept. Both are the same function.
