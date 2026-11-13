// YORO Recover: doctor sign-up with mobile number + password.
// Creates the login without sending any email. The login's internal email is
// d<mobile>@doctors.recover.yorohealth.com (never mailed). Doctor starts unapproved.
import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...CORS, "content-type": "application/json" } });
const str = (v: unknown, min: number, max: number) => typeof v === "string" && v.trim().length >= min && v.trim().length <= max ? v.trim() : null;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  let b: Record<string, unknown>;
  try { b = await req.json(); } catch { return json({ error: "bad_request" }, 400); }

  const mobile = String(b.mobile ?? "").replace(/\D/g, "").replace(/^(91|0)(?=\d{10}$)/, "");
  if (!/^[6-9]\d{9}$/.test(mobile)) return json({ error: "bad_mobile" }, 400);
  const password = typeof b.password === "string" ? b.password : "";
  if (password.length < 8 || password.length > 72) return json({ error: "bad_password" }, 400);
  const full_name = str(b.full_name, 2, 120), clinic = str(b.clinic, 2, 160), specialty = str(b.specialty, 2, 80), city = str(b.city, 2, 80);
  if (!full_name || !clinic || !specialty || !city) return json({ error: "missing_fields" }, 400);
  const council_no = str(b.council_no, 1, 40);

  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
  const { data: exists } = await admin.from("rc_doctors").select("id").eq("phone", mobile).maybeSingle();
  if (exists) return json({ error: "mobile_taken" }, 409);

  const email = `d${mobile}@doctors.recover.yorohealth.com`;
  const { data, error } = await admin.auth.admin.createUser({
    email, password, email_confirm: true,
    user_metadata: { rc_doctor: true, full_name, clinic, specialty, city, phone: mobile, council_no },
  });
  if (error) {
    if (/already/i.test(error.message)) return json({ error: "mobile_taken" }, 409);
    console.error("createUser", error.message);
    return json({ error: "failed" }, 500);
  }
  // Profile is created by a database trigger; make sure it exists.
  await admin.from("rc_doctors").upsert({ id: data.user.id, full_name, clinic, specialty, city, phone: mobile, council_no }, { onConflict: "id", ignoreDuplicates: true });
  return json({ ok: true, login: email });
});
