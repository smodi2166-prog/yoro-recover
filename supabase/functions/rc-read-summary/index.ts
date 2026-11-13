// YORO Recover: read a discharge summary (photo or PDF) and return fields to prefill enrolment.
// Nothing is stored. Needs the ANTHROPIC_API_KEY secret; returns 503 until it is set.
import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...CORS, "content-type": "application/json" } });
const TYPES = ["image/jpeg", "image/png", "image/webp", "application/pdf"];

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  const key = Deno.env.get("ANTHROPIC_API_KEY");
  if (!key) return json({ error: "not_enabled" }, 503);

  const auth = req.headers.get("authorization") ?? "";
  const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, { global: { headers: { authorization: auth } } });
  const { data: u } = await sb.auth.getUser();
  if (!u?.user) return json({ error: "login" }, 401);
  const { data: doc } = await sb.from("rc_doctors").select("verified").eq("id", u.user.id).maybeSingle();
  if (!doc?.verified) return json({ error: "not_verified" }, 403);

  let body: { media_type?: string; data?: string };
  try { body = await req.json(); } catch { return json({ error: "bad_request" }, 400); }
  if (!body.media_type || !TYPES.includes(body.media_type) || !body.data) return json({ error: "bad_file" }, 400);
  if (body.data.length > 7_000_000) return json({ error: "too_big" }, 413);

  const block = body.media_type === "application/pdf"
    ? { type: "document", source: { type: "base64", media_type: body.media_type, data: body.data } }
    : { type: "image", source: { type: "base64", media_type: body.media_type, data: body.data } };
  const prompt = `This is a hospital discharge summary or prescription from India. Extract these fields and reply with ONLY a JSON object, no other text:
{"patient_name": string|null, "procedure": string|null (main procedure or diagnosis, short), "discharge_date": "YYYY-MM-DD"|null, "followup_date": "YYYY-MM-DD"|null (date of the next visit/review; if only "after N days" is given, compute from the discharge date), "advice": string|null (activity, wound care, diet, physiotherapy, warning signs; short lines), "medicines": string|null (one per line: name, dose, how often, how long), "tests": string|null (blood tests or checkups due, with timing)}
Copy medicine names exactly as written. Use null for anything you cannot read. Do not guess.`;

  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({ model: Deno.env.get("RC_MODEL") ?? "claude-haiku-5-5", max_tokens: 1500, messages: [{ role: "user", content: [block, { type: "text", text: prompt }] }] }),
  });
  if (!r.ok) { console.error("anthropic", r.status, (await r.text()).slice(0, 300)); return json({ error: "read_failed" }, 502); }
  const out = await r.json();
  const text = (out.content ?? []).map((c: { text?: string }) => c.text ?? "").join("");
  const m = text.match(/\{[\s\S]*\}/);
  try { return json({ fields: JSON.parse(m ? m[0] : text) }); } catch { return json({ error: "read_failed" }, 502); }
});
