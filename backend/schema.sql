-- Run once in Supabase -> SQL Editor
create table if not exists vpas (
  id uuid primary key default gen_random_uuid(),
  vpa_normalized text unique not null,
  trusted_record boolean default false
);

create table if not exists reports (
  id uuid primary key default gen_random_uuid(),
  vpa_id uuid references vpas(id),
  reason text,
  request_id text,
  created_at timestamptz default now()
);

-- if you already created "reports" earlier, add the new columns:
alter table reports add column if not exists reason text;
alter table reports add column if not exists request_id text;
alter table reports add column if not exists created_at timestamptz default now();

insert into vpas (vpa_normalized, trusted_record) values
  ('demo_trusted_merchant@bank', true),
  ('demo_caution_unknown@okaxis', false),
  ('demo_flagged_scammer@paytm', false)
on conflict (vpa_normalized) do nothing;

-- give the demo scammer a report so it scans as RED
insert into reports (vpa_id, reason)
select id, 'demo seed' from vpas
where vpa_normalized = 'demo_flagged_scammer@paytm'
  and not exists (select 1 from reports r where r.vpa_id = vpas.id);

alter table vpas disable row level security;
alter table reports disable row level security;
