// YORO Recover doctor login with mobile number + 6-digit PIN.
// The PIN is never used as the password directly: password = HMAC(server key, mobile:PIN),
// so the only way to try PINs is through this function, which locks a number for 15 minutes
// after 5 wrong attempts.
// Actions: signup, login, reset (YORO staff only: sets a new random PIN for a doctor).
import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...CORS, "content-type": "application/json" } });
const str = (v: unknown, min: number, max: number) => typeof v === "string" && v.trim().length >= min && v.trim().length <= max ? v.trim() : null;
const normMobile = (v: unknown) => String(v ?? "").replace(/\D/g, "").replace(/^(91|0)(?=\d{10}$)/, "");
const emailFor = (m: string) => `d${m}@doctors.recover.yorohealth.com`;
const MAX_FAILS = 5, LOCK_MIN = 15;

const URL_ = Deno.env.get("SUPABASE_URL")!, ANON = Deno.env.get("SUPABASE_ANON_KEY")!;
const admin = createClient(URL_, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });

let pepperCache = "";
async function derive(mobile: string, pin: string) {
  if (!pepperCache) {
    const { data, error } = await admin.from("rc_secret").select("pepper").eq("id", 1).single();
    if (error || !data) throw new Error("no key");
    pepperCache = data.pepper;
  }
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(pepperCache), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(`${mobile}:${pin}`));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function signIn(mobile: string, pin: string) {
  const anon = createClient(URL_, ANON, { auth: { persistSession: false } });
  const { data, error } = await anon.auth.signInWithPassword({ email: emailFor(mobile), password: await derive(mobile, pin) });
  if (error || !data.session) return null;
  return { access_token: data.session.access_token, refresh_token: data.session.refresh_token };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  let b: Record<string, unknown>;
  try { b = await req.json(); } catch { return json({ error: "bad_request" }, 400); }

  if (b.action === "signup") {
    const mobile = normMobile(b.mobile), pin = String(b.pin ?? "");
    if (!/^[6-9]\d{9}$/.test(mobile)) return json({ error: "bad_mobile" }, 400);
    if (!/^\d{6}$/.test(pin)) return json({ error: "bad_pin" }, 400);
    if (/^(\d)\1{5}$/.test(pin) || ["123456", "654321", "012345", "234567"].includes(pin)) return json({ error: "weak_pin" }, 400);
    const full_name = str(b.full_name, 2, 120), clinic = str(b.clinic, 2, 160), specialty = str(b.specialty, 2, 80), city = str(b.city, 2, 80);
    if (!full_name || !clinic || !specialty || !city) return json({ error: "missing_fields" }, 400);
    const council_no = str(b.council_no, 1, 40);
    const { data: exists } = await admin.from("rc_doctors").select("id").eq("phone", mobile).maybeSingle();
    if (exists) return json({ error: "mobile_taken" }, 409);
    const { data, error } = await admin.auth.admin.createUser({
      email: emailFor(mobile), password: await derive(mobile, pin), email_confirm: true,
      user_metadata: { rc_doctor: true, full_name, clinic, specialty, city, phone: mobile, council_no },
    });
    if (error) return json({ error: /already/i.test(error.message) ? "mobile_taken" : "failed" }, /already/i.test(error.message) ? 409 : 500);
    await admin.from("rc_doctors").upsert({ id: data.user.id, full_name, clinic, specialty, city, phone: mobile, council_no }, { onConflict: "id", ignoreDuplicates: true });
    return json({ ok: true, session: await signIn(mobile, pin) });
  }

  if (b.action === "login") {
    const mobile = normMobile(b.mobile), pin = String(b.pin ?? "");
    if (!/^\d{10}$/.test(mobile) || !/^\d{6}$/.test(pin)) return json({ error: "wrong" }, 401);
    const { data: att } = await admin.from("rc_login_attempts").select("*").eq("mobile", mobile).maybeSingle();
    if (att?.locked_until && new Date(att.locked_until) > new Date()) {
      return json({ error: "locked", minutes: Math.ceil((new Date(att.locked_until).getTime() - Date.now()) / 60000) }, 429);
    }
    const session = await signIn(mobile, pin);
    if (!session) {
      const fails = (att?.locked_until ? 0 : att?.failures ?? 0) + 1;
      const lock = fails >= MAX_FAILS;
      await admin.from("rc_login_attempts").upsert({ mobile, failures: lock ? 0 : fails, locked_until: lock ? new Date(Date.now() + LOCK_MIN * 60000).toISOString() : null, updated_at: new Date().toISOString() });
      return lock ? json({ error: "locked", minutes: LOCK_MIN }, 429) : json({ error: "wrong", left: MAX_FAILS - fails }, 401);
    }
    if (att) await admin.from("rc_login_attempts").delete().eq("mobile", mobile);
    return json({ ok: true, session });
  }

  if (b.action === "reset") {
    const caller = createClient(URL_, ANON, { global: { headers: { authorization: req.headers.get("authorization") ?? "" } }, auth: { persistSession: false } });
    const { data: isAdmin } = await caller.rpc("rc_is_admin");
    if (isAdmin !== true) return json({ error: "forbidden" }, 403);
    const id = String(b.doctor_id ?? "");
    const { data: doc } = await admin.from("rc_doctors").select("id, phone").eq("id", id).maybeSingle();
    if (!doc) return json({ error: "not_found" }, 404);
    const mobile = normMobile(doc.phone);
    if (!/^\d{10}$/.test(mobile)) return json({ error: "bad_mobile" }, 400);
    let pin = "";
    do { pin = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0"); } while (/^(\d)\1{5}$/.test(pin));
    const { error } = await admin.auth.admin.updateUserById(doc.id, { email: emailFor(mobile), email_confirm: true, password: await derive(mobile, pin) });
    if (error) { console.error("reset", error.message); return json({ error: "failed" }, 500); }
    await admin.from("rc_doctors").update({ phone: mobile }).eq("id", doc.id);
    await admin.from("rc_login_attempts").delete().eq("mobile", mobile);
    return json({ ok: true, pin, mobile });
  }
  return json({ error: "bad_action" }, 400);
});
