# YORO Recover

Post-discharge check-ins that tell doctors exactly which patients to call back. By YORO Health.

- `index.html` landing page · `app.html` doctor portal · `check.html#<token>` patient check-in · `admin.html` doctor approval · `privacy.html` (draft)
- Static site on Netlify; database and login on Supabase (project `pglxotjvbcklzswziggs`, tables `rc_*`).
- `supabase/functions/rc-read-summary` reads discharge summaries (needs `ANTHROPIC_API_KEY` secret).
