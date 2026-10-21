-- =============================================================
-- CanteenConnect — Supabase setup (hardened)
-- Run this in: Supabase Dashboard -> SQL Editor -> New query
-- Safe to run twice (idempotent).
--
-- BEFORE YOU RUN: edit the two values in "STEP 0" below.
-- =============================================================

-- ---------- STEP 0: pick your admin ID + password ----------
-- The file NEVER stores them as plain text — only SHA-256 hashes.
-- Change 'CHANGE-ME-ID' and 'CHANGE-ME-PASSWORD' to your real values.
-- Keep a copy of the password somewhere safe (password manager).
do $$
begin
  if not exists (select 1 from pg_extension where extname = 'pgcrypto') then
    create extension pgcrypto;
  end if;
end $$;

create table if not exists admin_users (
  id_hash    text primary key,              -- sha256 of the admin id
  pass_hash  text not null,                 -- sha256 of the admin password
  created_at timestamptz default now()
);

-- Replace CHANGE-ME-ID / CHANGE-ME-PASSWORD, then run just this block.
insert into admin_users (id_hash, pass_hash)
values (
  encode(digest(lower(trim('CHANGE-ME-ID')), 'sha256'), 'hex'),
  encode(digest('CHANGE-ME-PASSWORD', 'sha256'), 'hex')
)
on conflict (id_hash) do nothing;

-- ---------- tables ----------
create table if not exists reviews (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null default auth.uid(),
  dish_id      text not null,
  stars        int  not null check (stars between 1 and 5),
  text         text check (length(coalesce(text,'')) <= 1000),
  display_name text not null check (length(display_name) between 1 and 30),
  photo_url    text,
  hidden       boolean not null default false,
  report_count int not null default 0,
  created_at   timestamptz not null default now()
);

create table if not exists review_reports (
  id          uuid primary key default gen_random_uuid(),
  review_id   uuid not null references reviews(id) on delete cascade,
  reported_by uuid not null default auth.uid(),
  reason      text not null,
  note        text check (length(coalesce(note,'')) <= 120),
  created_at  timestamptz not null default now(),
  unique (review_id, reported_by)          -- one report per student per review
);

create table if not exists menu_items (
  id          text primary key,
  name        text not null,
  price       numeric not null check (price > 0),
  description text,
  tags        text[] default array['snack'],
  gradient    text[],
  image       text,
  sort_order  int default 0
);

create table if not exists app_settings (
  key   text primary key,
  value text
);

-- one review per student per dish (the app checks this client-side too)
create unique index if not exists reviews_user_dish
  on reviews (user_id, dish_id);

create index if not exists reviews_dish_idx   on reviews (dish_id);
create index if not exists reports_review_idx on review_reports (review_id);

-- start with no counter code = the join gate stays open (fail open)
insert into app_settings (key, value) values ('join_code', '')
on conflict (key) do nothing;

-- ---------- RLS: the real security boundary ----------
alter table reviews        enable row level security;
alter table review_reports enable row level security;
alter table menu_items     enable row level security;
alter table app_settings   enable row level security;

-- reviews: everybody reads; a student may insert ONLY as themselves;
-- only their own review can be deleted by them; updates are admin-only
-- (through the security-definer functions below).
drop policy if exists "reviews read"   on reviews;
drop policy if exists "reviews insert" on reviews;
drop policy if exists "reviews delete" on reviews;
create policy "reviews read" on reviews for select using (true);
create policy "reviews insert" on reviews for insert to authenticated
  with check (
    user_id = auth.uid()
    and stars between 1 and 5
    and length(coalesce(text,'')) <= 1000
    and length(display_name) between 1 and 30
  );
create policy "reviews delete" on reviews for delete to authenticated
  using (user_id = auth.uid());

-- reports: a student writes only as themselves and reads only their own
drop policy if exists "reports read"   on review_reports;
drop policy if exists "reports insert" on review_reports;
create policy "reports read" on review_reports for select to authenticated
  using (reported_by = auth.uid());
create policy "reports insert" on review_reports for insert to authenticated
  with check (reported_by = auth.uid());

-- menu: everyone reads, nobody writes directly (admin_menu_save() does)
drop policy if exists "menu read" on menu_items;
create policy "menu read" on menu_items for select using (true);

-- app_settings: NO policy at all -> the join code is unreadable from the
-- browser. Only get_join_code() / rotate_join_code() below can touch it.
revoke all on app_settings from anon, authenticated;

-- =============================================================
-- helper: admin check (used by every admin function)
-- =============================================================
create or replace function is_admin(p_id text, p_password text)
returns boolean language sql security definer set search_path = public as $$
  select exists(
    select 1 from admin_users
    where id_hash   = encode(digest(lower(trim(p_id)), 'sha256'), 'hex')
      and pass_hash = encode(digest(p_password, 'sha256'), 'hex')
  );
$$;

-- =============================================================
-- admin functions (security definer = bypass RLS on purpose)
-- =============================================================

-- login check, with a simple brute-force brake:
-- after 20 wrong tries within 15 minutes everything is locked for 15 min
create table if not exists admin_attempts (
  at  timestamptz not null default now(),
  ok  boolean not null
);

create or replace function verify_admin(p_id text, p_password text)
returns boolean language plpgsql security definer set search_path = public as $$
declare
  ok boolean;
  fails int;
begin
  select count(*) into fails from admin_attempts
    where ok = false and at > now() - interval '15 minutes';
  if fails >= 20 then
    return false;
  end if;

  ok := is_admin(p_id, p_password);
  insert into admin_attempts(ok) values (ok);
  delete from admin_attempts where at < now() - interval '1 day';
  return ok;
end $$;

-- only the admin can READ the counter code
create or replace function get_join_code(p_id text, p_password text)
returns text language plpgsql security definer set search_path = public as $$
begin
  if not is_admin(p_id, p_password) then return null; end if;
  return coalesce((select value from app_settings where key = 'join_code'), '');
end $$;

-- only the admin can ROTATE the counter code
create or replace function rotate_join_code(p_id text, p_password text, p_code text)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  if not is_admin(p_id, p_password) then return false; end if;
  insert into app_settings(key, value) values ('join_code', upper(left(coalesce(p_code,''),12)))
  on conflict (key) do update set value = excluded.value;
  return true;
end $$;

-- a STUDENT redeems the code; the answer is just true / false
-- (empty code in the table = gate disabled = always true)
create or replace function redeem_join_code(p_code text)
returns boolean language plpgsql security definer set search_path = public as $$
declare live text;
begin
  select value into live from app_settings where key = 'join_code';
  if live is null or live = '' then return true; end if;
  return upper(trim(coalesce(p_code,''))) = upper(live);
end $$;

-- admin saves the whole menu (matches the keys the app sends:
--  id, name, price, desc, tags, gradient, image)
create or replace function admin_menu_save(p_id text, p_password text, p_menu jsonb)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  if not is_admin(p_id, p_password) then return false; end if;
  delete from menu_items;
  insert into menu_items (id, name, price, description, tags, gradient, image, sort_order)
  select
    left(x.id, 60),
    left(x.name, 80),
    x.price::numeric,
    left(coalesce(x."desc",''), 300),
    coalesce(x.tags, array['snack']::text[]),
    x.gradient,
    x.image,
    x.rn
  from (
    select row_number() over () as rn, m.*
    from jsonb_to_recordset(p_menu)
      as m(id text, name text, price numeric, "desc" text,
           tags text[], gradient text[], image text)
  ) x
  order by x.rn;
  return true;
end $$;

-- admin moderation — allowed only after 3 different students reported
create or replace function admin_moderate_review(p_id text, p_password text,
                                                p_review_id uuid, p_action text)
returns boolean language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not is_admin(p_id, p_password) then return false; end if;

  select count(distinct reported_by) into n
    from review_reports where review_id = p_review_id;
  if n < 3 then return false; end if;      -- the 3-report rule, on the server

  if p_action = 'hide' then
    update reviews set hidden = true where id = p_review_id;
  elsif p_action = 'show' then
    update reviews set hidden = false where id = p_review_id;
  elsif p_action = 'delete' then
    delete from reviews where id = p_review_id;
  elsif p_action = 'dismiss' then
    delete from review_reports where review_id = p_review_id;
    update reviews set hidden = false, report_count = 0 where id = p_review_id;
  else
    return false;
  end if;
  return true;
end $$;

-- a student reports a review (one report per student, counted server-side)
create or replace function report_review(p_review_id uuid, p_reason text, p_note text)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return false; end if;
  insert into review_reports (review_id, reported_by, reason, note)
  values (p_review_id, auth.uid(),
          left(coalesce(p_reason,'Other'), 40),
          left(coalesce(p_note,''), 120))
  on conflict (review_id, reported_by) do nothing;

  update reviews set report_count =
    (select count(*) from review_reports where review_id = p_review_id)
  where id = p_review_id;
  return true;
end $$;

-- each student reads only their own reports
create or replace function my_reports()
returns setof review_reports language sql security definer set search_path = public as $$
  select * from review_reports where reported_by = auth.uid();
$$;

-- a student renames themselves on all of their own reviews (1-30 chars)
create or replace function update_my_name(p_name text)
returns boolean language plpgsql security definer set search_path = public as $$
declare n text := trim(coalesce(p_name,''));
begin
  if auth.uid() is null then return false; end if;
  if length(n) < 1 or length(n) > 30 then return false; end if;
  update reviews set display_name = n where user_id = auth.uid();
  return true;
end $$;

-- ---------- grants ----------
revoke all on function is_admin(text,text), verify_admin(text,text),
  get_join_code(text,text), rotate_join_code(text,text,text),
  redeem_join_code(text), admin_menu_save(text,text,jsonb),
  admin_moderate_review(text,text,uuid,text),
  report_review(uuid,text,text), my_reports(), update_my_name(text) from public;

grant execute on function verify_admin(text,text) to anon, authenticated;
grant execute on function get_join_code(text,text) to anon, authenticated;
grant execute on function rotate_join_code(text,text,text) to anon, authenticated;
grant execute on function redeem_join_code(text) to anon, authenticated;
grant execute on function admin_menu_save(text,text,jsonb) to anon, authenticated;
grant execute on function admin_moderate_review(text,text,uuid,text) to anon, authenticated;
grant execute on function report_review(uuid,text,text) to authenticated;
grant execute on function my_reports() to authenticated;
grant execute on function update_my_name(text) to authenticated;

-- =============================================================
-- STORAGE: review-photos bucket
-- =============================================================
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('review-photos', 'review-photos', true, 5242880,
        array['image/jpeg','image/png','image/webp'])
on conflict (id) do update
  set public = true,
      file_size_limit = 5242880,
      allowed_mime_types = array['image/jpeg','image/png','image/webp'];

drop policy if exists "photos read"   on storage.objects;
drop policy if exists "photos upload" on storage.objects;
drop policy if exists "photos delete" on storage.objects;

create policy "photos read" on storage.objects for select
  using (bucket_id = 'review-photos');

-- uploads need a session (students after login, admin panel through the
-- anonymous sign-in) -> Supabase -> Auth -> Providers -> Anonymous = ON
create policy "photos upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'review-photos');

-- deleting an object is allowed only to the one who uploaded it
create policy "photos delete" on storage.objects for delete to authenticated
  using (bucket_id = 'review-photos' and owner = auth.uid());

-- =============================================================
-- DONE. Now check in the dashboard:
--   Auth -> Email Templates   : use {{ .Token }} for the 6-digit code
--   Auth -> Providers -> Google : ON, redirect URL = your site
--   Auth -> Providers -> Anonymous sign-ins : ON  (needed for admin photos)
-- =============================================================
