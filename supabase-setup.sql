-- BMC SWOT Assessment — Supabase schema v3
-- Run this in the Supabase SQL Editor. Safe to re-run: idempotent.
-- Upgrades v1/v2 in place. No data loss.
--
-- What changed vs v2:
--   * Respondents are now identified by an opaque UUID token (stored in the
--     browser), not by their typed name. Fixes collisions ("Max" vs "Max" vs
--     "max") and impersonation.
--   * A new `respondents` table tracks display name, role, and submission time.
--   * All writes go through SECURITY DEFINER RPCs. Anon has zero direct
--     INSERT/UPDATE/DELETE/SELECT on the data tables. This closes the
--     "anon can UPDATE any row" hole in v2 (including overwriting someone
--     else's answers or flipping `closed` on an assessment).
--   * Owner key rotation is no longer possible from anon.

create extension if not exists pgcrypto;

-- =========================================================
-- 1. Tables
-- =========================================================

create table if not exists assessments (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  created_at  timestamptz not null default now(),
  created_by  text,
  owner_key   text not null default replace(gen_random_uuid()::text,'-',''),
  closed      boolean not null default false
);

-- v1 → v2 upgrade path (safe if already applied)
alter table assessments add column if not exists owner_key text;
update assessments set owner_key = replace(gen_random_uuid()::text,'-','') where owner_key is null;
alter table assessments alter column owner_key set not null;

-- NEW in v3: respondents table.
create table if not exists respondents (
  assessment_id    uuid not null references assessments(id) on delete cascade,
  respondent_token uuid not null,
  name             text not null,
  role             text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  submitted_at     timestamptz,
  primary key (assessment_id, respondent_token)
);
create index if not exists respondents_assessment_idx on respondents(assessment_id);

create table if not exists responses (
  id               uuid primary key default gen_random_uuid(),
  assessment_id    uuid not null references assessments(id) on delete cascade,
  respondent_name  text not null,
  respondent_role  text,
  block_key        text not null,
  statement_sign   text not null check (statement_sign in ('+','-')),
  statement_index  int  not null,
  statement_text   text not null,
  score            int  not null check (score between 0 and 5),
  comment          text,
  updated_at       timestamptz not null default now()
);

-- v2 → v3: add respondent_token, backfill, swap unique constraint.
alter table responses add column if not exists respondent_token uuid;

do $$
declare r record; t uuid;
begin
  for r in
    select distinct assessment_id, respondent_name
      from responses where respondent_token is null
  loop
    t := gen_random_uuid();
    update responses set respondent_token = t
     where assessment_id = r.assessment_id
       and respondent_name = r.respondent_name
       and respondent_token is null;
    insert into respondents(assessment_id, respondent_token, name)
      values (r.assessment_id, t, r.respondent_name)
      on conflict do nothing;
  end loop;
end $$;

alter table responses alter column respondent_token set not null;

-- Drop any old v2 unique constraint (column set: assessment_id, respondent_name, block_key, sign, idx)
do $$
declare old_conname text;
begin
  select c.conname into old_conname
  from pg_constraint c
  where c.conrelid = 'public.responses'::regclass
    and c.contype = 'u'
    and (
      select array_agg(a.attname::text order by a.attname::text)
      from pg_attribute a
      where a.attrelid = 'public.responses'::regclass
        and a.attnum = any(c.conkey)
    ) = array['assessment_id','block_key','respondent_name','statement_index','statement_sign']::text[]
  limit 1;
  if old_conname is not null then
    execute format('alter table public.responses drop constraint %I', old_conname);
  end if;
end $$;

-- Add the v3 unique constraint if missing.
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.responses'::regclass
      and conname  = 'responses_unique_per_statement'
  ) then
    alter table responses
      add constraint responses_unique_per_statement
      unique (assessment_id, respondent_token, block_key, statement_sign, statement_index);
  end if;
end $$;

create table if not exists external_notes (
  id               uuid primary key default gen_random_uuid(),
  assessment_id    uuid not null references assessments(id) on delete cascade,
  respondent_name  text not null,
  force_category   text not null,
  note_type        text not null check (note_type in ('opportunity','threat')),
  note             text not null,
  priority         int check (priority between 1 and 5),
  created_at       timestamptz not null default now()
);

alter table external_notes add column if not exists respondent_token uuid;

-- Backfill external_notes tokens by matching respondent_name within each assessment.
update external_notes en
   set respondent_token = r.respondent_token
  from respondents r
 where en.respondent_token is null
   and en.assessment_id = r.assessment_id
   and en.respondent_name = r.name;

-- Any stragglers (respondent_name not in respondents): create a token for them.
do $$
declare r record; t uuid;
begin
  for r in
    select distinct assessment_id, respondent_name
      from external_notes where respondent_token is null
  loop
    t := gen_random_uuid();
    update external_notes set respondent_token = t
     where assessment_id = r.assessment_id
       and respondent_name = r.respondent_name
       and respondent_token is null;
    insert into respondents(assessment_id, respondent_token, name)
      values (r.assessment_id, t, r.respondent_name)
      on conflict do nothing;
  end loop;
end $$;

alter table external_notes alter column respondent_token set not null;

create index if not exists responses_assessment_idx    on responses(assessment_id);
create index if not exists responses_token_idx         on responses(assessment_id, respondent_token);
create index if not exists external_assessment_idx    on external_notes(assessment_id);
create index if not exists external_token_idx         on external_notes(assessment_id, respondent_token);

-- =========================================================
-- 2. Lock everything down. All writes go through RPCs.
-- =========================================================

alter table assessments    enable row level security;
alter table respondents    enable row level security;
alter table responses      enable row level security;
alter table external_notes enable row level security;

-- Drop every policy we've ever created, to reset cleanly.
do $$
declare p record;
begin
  for p in
    select schemaname, tablename, policyname
      from pg_policies
     where schemaname = 'public'
       and tablename in ('assessments','respondents','responses','external_notes')
  loop
    execute format('drop policy %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end $$;

-- No policies = no access for anon on any of these tables. Good.
-- Revoke any stale grants in case old schemas issued them.
revoke all on assessments, respondents, responses, external_notes from anon, authenticated;

-- =========================================================
-- 3. Public-safe view of assessments (no owner_key column)
-- =========================================================
drop view if exists assessments_public;
create view assessments_public with (security_invoker = off) as
  select id, name, created_at, created_by, closed from assessments;

grant select on assessments_public to anon, authenticated;

-- =========================================================
-- 4. RPCs — the ONLY way to read or write.
-- =========================================================

-- 4a. Create an assessment. Returns owner_key to the creator (visible once).
drop function if exists create_assessment(text, text);
create or replace function create_assessment(p_name text, p_created_by text)
returns table (id uuid, name text, owner_key text, created_at timestamptz)
language plpgsql security definer set search_path = public as $$
declare new_row assessments%rowtype;
begin
  if coalesce(trim(p_name), '') = '' then
    raise exception 'name required';
  end if;
  insert into assessments(name, created_by)
    values (p_name, p_created_by)
    returning * into new_row;
  return query select new_row.id, new_row.name, new_row.owner_key, new_row.created_at;
end $$;

-- 4b. Upsert the respondent's display name/role. Called when they "Save & begin".
drop function if exists upsert_respondent(uuid, uuid, text, text);
create or replace function upsert_respondent(
  p_assessment_id uuid, p_respondent_token uuid,
  p_name text, p_role text
) returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_respondent_token is null then raise exception 'respondent_token required'; end if;
  if coalesce(trim(p_name), '') = '' then raise exception 'name required'; end if;
  -- Block writes after submission — they must explicitly unsubmit to edit again.
  if exists (
    select 1 from respondents
     where assessment_id = p_assessment_id
       and respondent_token = p_respondent_token
       and submitted_at is not null
  ) then
    raise exception 'already submitted; unsubmit first' using errcode = 'P0001';
  end if;
  insert into respondents(assessment_id, respondent_token, name, role)
    values (p_assessment_id, p_respondent_token, p_name, p_role)
    on conflict (assessment_id, respondent_token)
    do update set name = excluded.name, role = excluded.role, updated_at = now();
end $$;

-- 4c. Upsert a single response. Respondent name/role come from respondents.
drop function if exists upsert_response(uuid, uuid, text, text, int, text, int, text);
create or replace function upsert_response(
  p_assessment_id uuid, p_respondent_token uuid,
  p_block_key text, p_sign text, p_idx int,
  p_statement_text text, p_score int, p_comment text
) returns void
language plpgsql security definer set search_path = public as $$
declare r respondents%rowtype;
begin
  select * into r from respondents
   where assessment_id = p_assessment_id and respondent_token = p_respondent_token;
  if not found then
    raise exception 'unknown respondent — call upsert_respondent first' using errcode = 'P0001';
  end if;
  if r.submitted_at is not null then
    raise exception 'already submitted' using errcode = 'P0001';
  end if;
  if p_sign not in ('+','-') then raise exception 'bad sign'; end if;
  if p_score < 0 or p_score > 5 then raise exception 'score out of range'; end if;

  insert into responses(
    assessment_id, respondent_token, respondent_name, respondent_role,
    block_key, statement_sign, statement_index, statement_text, score, comment, updated_at
  ) values (
    p_assessment_id, p_respondent_token, r.name, r.role,
    p_block_key, p_sign, p_idx, p_statement_text, p_score, p_comment, now()
  )
  on conflict (assessment_id, respondent_token, block_key, statement_sign, statement_index)
  do update set
    score = excluded.score,
    comment = excluded.comment,
    statement_text = excluded.statement_text,
    respondent_name = excluded.respondent_name,
    respondent_role = excluded.respondent_role,
    updated_at = now();
end $$;

-- 4d. Submit / unsubmit. Respondent-initiated lock.
drop function if exists submit_assessment(uuid, uuid);
create or replace function submit_assessment(p_assessment_id uuid, p_respondent_token uuid)
returns timestamptz
language plpgsql security definer set search_path = public as $$
declare ts timestamptz := now();
begin
  update respondents set submitted_at = ts, updated_at = ts
   where assessment_id = p_assessment_id and respondent_token = p_respondent_token;
  if not found then raise exception 'unknown respondent'; end if;
  return ts;
end $$;

drop function if exists unsubmit_assessment(uuid, uuid);
create or replace function unsubmit_assessment(p_assessment_id uuid, p_respondent_token uuid)
returns void
language plpgsql security definer set search_path = public as $$
begin
  update respondents set submitted_at = null, updated_at = now()
   where assessment_id = p_assessment_id and respondent_token = p_respondent_token;
  if not found then raise exception 'unknown respondent'; end if;
end $$;

-- 4e. External notes — insert & delete. Token-validated.
drop function if exists insert_external_note(uuid, uuid, text, text, text, int);
create or replace function insert_external_note(
  p_assessment_id uuid, p_respondent_token uuid,
  p_force text, p_type text, p_note text, p_priority int
) returns uuid
language plpgsql security definer set search_path = public as $$
declare r respondents%rowtype; new_id uuid;
begin
  select * into r from respondents
   where assessment_id = p_assessment_id and respondent_token = p_respondent_token;
  if not found then raise exception 'unknown respondent' using errcode = 'P0001'; end if;
  if r.submitted_at is not null then raise exception 'already submitted' using errcode = 'P0001'; end if;
  if p_type not in ('opportunity','threat') then raise exception 'bad note_type'; end if;
  if p_priority is not null and (p_priority < 1 or p_priority > 5) then raise exception 'priority out of range'; end if;
  if coalesce(trim(p_note),'') = '' then raise exception 'note required'; end if;

  insert into external_notes(
    assessment_id, respondent_token, respondent_name, force_category, note_type, note, priority
  ) values (
    p_assessment_id, p_respondent_token, r.name, p_force, p_type, p_note, p_priority
  ) returning id into new_id;
  return new_id;
end $$;

drop function if exists delete_my_external_note(uuid, text);  -- old v2 signature
drop function if exists delete_my_external_note(uuid, uuid);
create or replace function delete_my_external_note(p_id uuid, p_respondent_token uuid)
returns boolean
language plpgsql security definer set search_path = public as $$
declare removed int;
begin
  delete from external_notes
    where id = p_id and respondent_token = p_respondent_token;
  get diagnostics removed = row_count;
  return removed > 0;
end $$;

-- 4f. Respondent-side reads (load "my" answers so I can resume).
drop function if exists get_my_responses(uuid, text);        -- old v2
drop function if exists get_my_responses(uuid, uuid);
create or replace function get_my_responses(p_assessment_id uuid, p_respondent_token uuid)
returns table (
  block_key text, statement_sign text, statement_index int,
  score int, comment text
)
language sql security definer set search_path = public as $$
  select block_key, statement_sign, statement_index, score, comment
    from responses
   where assessment_id = p_assessment_id
     and respondent_token = p_respondent_token;
$$;

drop function if exists get_my_external(uuid, text);         -- old v2
drop function if exists get_my_external(uuid, uuid);
create or replace function get_my_external(p_assessment_id uuid, p_respondent_token uuid)
returns table (
  id uuid, force_category text, note_type text, note text, priority int
)
language sql security definer set search_path = public as $$
  select id, force_category, note_type, note, priority
    from external_notes
   where assessment_id = p_assessment_id
     and respondent_token = p_respondent_token;
$$;

drop function if exists get_my_respondent(uuid, uuid);
create or replace function get_my_respondent(p_assessment_id uuid, p_respondent_token uuid)
returns table (name text, role text, submitted_at timestamptz)
language sql security definer set search_path = public as $$
  select name, role, submitted_at
    from respondents
   where assessment_id = p_assessment_id
     and respondent_token = p_respondent_token;
$$;

-- 4g. Owner-side dashboard reads (gated by owner_key).
create or replace function _check_owner(p_assessment_id uuid, p_owner_key text)
returns void
language plpgsql security definer set search_path = public as $$
declare expected text;
begin
  select owner_key into expected from assessments where id = p_assessment_id;
  if expected is null then raise exception 'assessment not found'; end if;
  if expected <> p_owner_key then
    raise exception 'invalid owner key' using errcode = '42501';
  end if;
end $$;

drop function if exists get_dashboard_responses(uuid, text);
create or replace function get_dashboard_responses(p_assessment_id uuid, p_owner_key text)
returns table (
  respondent_token uuid, respondent_name text, respondent_role text,
  block_key text, statement_sign text, statement_index int,
  statement_text text, score int, comment text, updated_at timestamptz
)
language plpgsql security definer set search_path = public as $$
begin
  perform _check_owner(p_assessment_id, p_owner_key);
  return query
    select r.respondent_token, r.respondent_name, r.respondent_role,
           r.block_key, r.statement_sign, r.statement_index,
           r.statement_text, r.score, r.comment, r.updated_at
      from responses r
     where r.assessment_id = p_assessment_id;
end $$;

drop function if exists get_dashboard_external(uuid, text);
create or replace function get_dashboard_external(p_assessment_id uuid, p_owner_key text)
returns table (
  id uuid, respondent_token uuid, respondent_name text,
  force_category text, note_type text, note text, priority int, created_at timestamptz
)
language plpgsql security definer set search_path = public as $$
begin
  perform _check_owner(p_assessment_id, p_owner_key);
  return query
    select n.id, n.respondent_token, n.respondent_name,
           n.force_category, n.note_type, n.note, n.priority, n.created_at
      from external_notes n
     where n.assessment_id = p_assessment_id;
end $$;

drop function if exists get_dashboard_respondents(uuid, text);
create or replace function get_dashboard_respondents(p_assessment_id uuid, p_owner_key text)
returns table (
  respondent_token uuid, name text, role text,
  created_at timestamptz, submitted_at timestamptz,
  response_count bigint
)
language plpgsql security definer set search_path = public as $$
begin
  perform _check_owner(p_assessment_id, p_owner_key);
  return query
    select r.respondent_token, r.name, r.role, r.created_at, r.submitted_at,
           (select count(*) from responses x
             where x.assessment_id = r.assessment_id
               and x.respondent_token = r.respondent_token
               and x.score > 0) as response_count
      from respondents r
     where r.assessment_id = p_assessment_id
     order by r.created_at;
end $$;

-- 4h. Close / reopen an assessment (owner only).
drop function if exists set_assessment_closed(uuid, text, boolean);
create or replace function set_assessment_closed(p_assessment_id uuid, p_owner_key text, p_closed boolean)
returns void
language plpgsql security definer set search_path = public as $$
begin
  perform _check_owner(p_assessment_id, p_owner_key);
  update assessments set closed = p_closed where id = p_assessment_id;
end $$;

-- =========================================================
-- 5. Grants
-- =========================================================

grant execute on function create_assessment(text, text)              to anon, authenticated;
grant execute on function upsert_respondent(uuid, uuid, text, text)  to anon, authenticated;
grant execute on function upsert_response(uuid, uuid, text, text, int, text, int, text) to anon, authenticated;
grant execute on function submit_assessment(uuid, uuid)              to anon, authenticated;
grant execute on function unsubmit_assessment(uuid, uuid)            to anon, authenticated;
grant execute on function insert_external_note(uuid, uuid, text, text, text, int) to anon, authenticated;
grant execute on function delete_my_external_note(uuid, uuid)        to anon, authenticated;
grant execute on function get_my_responses(uuid, uuid)               to anon, authenticated;
grant execute on function get_my_external(uuid, uuid)                to anon, authenticated;
grant execute on function get_my_respondent(uuid, uuid)              to anon, authenticated;
grant execute on function get_dashboard_responses(uuid, text)        to anon, authenticated;
grant execute on function get_dashboard_external(uuid, text)         to anon, authenticated;
grant execute on function get_dashboard_respondents(uuid, text)      to anon, authenticated;
grant execute on function set_assessment_closed(uuid, text, boolean) to anon, authenticated;

-- _check_owner is a helper — callable only from SECURITY DEFINER functions above.
revoke all on function _check_owner(uuid, text) from public, anon, authenticated;
