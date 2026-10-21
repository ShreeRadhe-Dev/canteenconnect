# CanteenConnect — Action Plan (tumhara checklist)

Sab code fixes ho chuke hain. Neeche sirf woh kaam hai jo **tumhe** dashboard
me karna hai (mere paas Supabase/Netlify access nahi hai).

---

## Step 1 — Deploy karo (5 min)

`canteenconnect-fixed/` ke saare files apni site ke root me daalo:

- `index.html` (patched — photo fix, English text, real QR, join gate, XSS fix)
- `canteenconnect-supabase.sql`
- `_headers`, `robots.txt`, `sitemap.xml`

> Agar tum Netlify pe git se deploy karte ho → repo me ye files commit + push.
> Agar drag-and-drop karte ho → poora folder drop kar do.

---

## Step 2 — Supabase SQL run karo (5 min)

1. `canteenconnect-supabase.sql` kholo → **CHANGE-ME-ID** aur
   **CHANGE-ME-PASSWORD** apne asli admin ID/password se badlo
2. Supabase Dashboard → **SQL Editor → New query** → poora paste → **Run**
3. Ek kaam aur: purane plain-text admin values (agar kahin hain) hata do

---

## Step 3 — Supabase settings (15 min) — **sabse zaroori**

| Kahan | Kya karna hai |
|---|---|
| **Auth → Providers → Anonymous sign-ins** | **ON** — ye OFF hone se hi admin photos upload nahi ho rahi thi |
| **Auth → Email Templates** | 4 templates (Confirm signup, Magic Link, Recovery, Change Email) me `{{ .Token }}` lagao — tabhi mail me 6-digit code aayega |
| **Auth → SMTP** (Brevo) | Host `smtp-relay.brevo.com`, Port `587`, User = Brevo SMTP login, Password = Brevo **SMTP key** (dashboard password nahi). Sender = Brevo me verified email |
| **Auth → Providers → Google** | ON + Redirect URL: `https://canteenconnect-shreeradhe.netlify.app/` |
| **Storage → review-photos** | bucket public + 5MB limit (SQL ne bana diya — sirf check kar lo) |

Brevo side: **SMTP & API → SMTP** se key banao, aur sender/domain verify
(SPF + DKIM) karo warna OTP spam me jayega.

---

## Step 4 — Accounts ki security (5 min)

- Supabase account → **2FA ON**
- Netlify account → **2FA ON**
- Admin ID/password kisi ko mat do, password manager me rakho

---

## Step 5 — Test karo (10 min)

1. **Photo test**: Admin → Menu Manager → kisi dish ka photo lagao →
   **refresh** → photo ab nahi jaani chahiye ✅
   (agar warning aaye "Photo upload failed" → Step 3 ka Anonymous sign-ins check karo)
2. **QR test**: Admin → Counter QR → "🔄 New code" → phone camera se scan karo
   → site khulni chahiye aur gate unlock hona chahiye
3. **Gate test**: galat code daal ke dekho → reject hona chahiye
4. **Email test**: naye email se sign up karo → 6-digit code mail me aana chahiye
5. **RLS test**: do alag account banao → ek ka review dusre se delete karne
   ki koshish karo → **nahi** delete hona chahiye

---

## Files me kya-kya fix hua (index.html)

1. ✅ Photo problem — compression (1600px), base64 ab refresh ke baad bhi
   dikhega, upload fail ho to saaf warning
2. ✅ `images/*.jpg` 404 the → ab gradient placeholder dikhega (jab tak
   photo upload na karo)
3. ✅ Hinglish → English (report modal + login error)
4. ✅ QR ab browser me hi banta hai (third-party website hata di)
5. ✅ Join gate ab server par validate hota hai (`redeem_join_code`)
6. ✅ Counter code ab padha nahi ja sakta (`get_join_code` = admin only)
7. ✅ Price field escaping (XSS fix) + "✓ Verified" badge ab sirf real
   accounts par
8. ✅ `_headers` (security headers + CSP), `robots.txt`, `sitemap.xml`
9. ✅ Join code ab `crypto.getRandomValues` se banta hai (Math.random nahi)

---

## Baaki suggestions (mere opinion — jab time mile)

1. **Admin ko Supabase Auth account banao** (long-term) — abhi password har
   request me plain text jaata hai; JWT session se wo bhi safe ho jayega
2. **Google Fonts self-host karo** — page thoda fast hoga, third-party call bhi hat jayegi
3. **"Remember this device" ki expiry** (30 din) — shared lab computer par safe
4. **og:image** add karo (social media share par thumbnail aayega)
5. **Backup**: Supabase free plan me automatic backup nahi hota — hafte me
   ek baar Database → Export ya `pg_dump` se backup le lo
6. App icon PNG me banao (iOS SVG home-screen icon support nahi karta)
