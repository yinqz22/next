-- next v2: im Supabase SQL Editor ausführen (Dashboard -> SQL Editor -> New query).
-- Das Skript ist wiederholbar: du kannst es komplett erneut ausführen, ohne dass etwas kaputtgeht.
-- Ohne dieses Skript funktionieren Profilbild-Upload, "Konto löschen", eindeutige Namen und die Nutzer-ID nicht.
-- Theme, Sprache und Sichtbarkeit brauchen es NICHT (die liegen in den User-Metadaten).

-- 1) Öffentlicher Bucket für Profilbilder (jeder Nutzer darf nur in seinen eigenen Ordner schreiben)
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true)
on conflict (id) do nothing;

drop policy if exists "avatars lesen" on storage.objects;
drop policy if exists "avatars hochladen" on storage.objects;
drop policy if exists "avatars ueberschreiben" on storage.objects;
drop policy if exists "avatars loeschen" on storage.objects;

create policy "avatars lesen" on storage.objects
  for select using (bucket_id = 'avatars');

create policy "avatars hochladen" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

create policy "avatars ueberschreiben" on storage.objects
  for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

create policy "avatars loeschen" on storage.objects
  for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- 2) Funktion, mit der sich ein eingeloggter Nutzer selbst löschen kann
create or replace function public.delete_user()
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if auth.uid() is null then
    raise exception 'not authenticated';
  end if;
  delete from auth.users where id = auth.uid();
end;
$$;

revoke all on function public.delete_user() from public, anon;
grant execute on function public.delete_user() to authenticated;

-- 3) Profile: eindeutiger Benutzername + 22-stellige Nutzer-ID
--    Jeder sieht nur sein eigenes Profil (inkl. ID). Die ID wird serverseitig vergeben und lässt sich nicht ändern.
create table if not exists public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  user_code  text not null unique check (user_code ~ '^next-[1-9][0-9]{21}$'),
  username   text not null check (char_length(username) between 2 and 32 and username = btrim(username)),
  created_at timestamptz not null default now()
);

-- Name ist eindeutig, Groß-/Kleinschreibung egal ("Tim" und "tim" sind derselbe Name)
create unique index if not exists profiles_username_key on public.profiles (lower(username));

-- v2-Migration: Nutzer-IDs heißen jetzt "next-" + 22 Ziffern (bestehende IDs bekommen das Präfix, Eindeutigkeit bleibt durch UNIQUE garantiert)
alter table public.profiles drop constraint if exists profiles_user_code_check;
update public.profiles set user_code = 'next-' || user_code where user_code !~ '^next-';
alter table public.profiles add constraint profiles_user_code_check check (user_code ~ '^next-[1-9][0-9]{21}$');

-- 22-stellige Zufalls-ID (erste Ziffer nie 0)
create or replace function public.gen_user_code()
returns text
language plpgsql
as $$
declare
  b bytea := decode(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 'hex');
  code text;
  i int;
begin
  code := (get_byte(b, 0) % 9 + 1)::text;
  for i in 1..21 loop
    code := code || (get_byte(b, i) % 10)::text;
  end loop;
  return 'next-' || code;
end;
$$;

-- Legt ein Profil an; ist der Wunschname schon vergeben, wird eine Zahl angehängt (Tim, Tim1, Tim2 ...)
create or replace function public.create_profile(uid uuid, mail text, meta jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  base text;
  candidate text;
  n int := 0;
  tries int := 0;
begin
  if exists (select 1 from public.profiles where id = uid) then
    return;
  end if;

  base := coalesce(
    nullif(btrim(meta ->> 'full_name'), ''),
    nullif(btrim(meta ->> 'name'), ''),
    nullif(btrim(split_part(coalesce(mail, ''), '@', 1)), ''),
    'User'
  );
  base := btrim(left(regexp_replace(base, '\s+', ' ', 'g'), 32));
  if char_length(base) < 2 then
    base := 'User';
  end if;
  base := upper(left(base, 1)) || substr(base, 2);
  candidate := base;

  loop
    tries := tries + 1;
    if tries > 200 then
      raise exception 'could not create profile';
    end if;
    begin
      insert into public.profiles (id, user_code, username)
      values (uid, public.gen_user_code(), candidate);
      return;
    exception when unique_violation then
      if exists (select 1 from public.profiles where lower(username) = lower(candidate)) then
        n := n + 1;
        candidate := btrim(left(base, 32 - char_length(n::text))) || n::text;
      end if;
    end;
  end loop;
end;
$$;

-- Bei jeder neuen Registrierung automatisch ein Profil anlegen
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform public.create_profile(new.id, new.email, new.raw_user_meta_data);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Bestehende Konten bekommen nachträglich ein Profil (Namen aus den bisherigen Daten)
do $$
declare
  r record;
begin
  for r in
    select u.id, u.email, u.raw_user_meta_data
    from auth.users u
    where not exists (select 1 from public.profiles p where p.id = u.id)
    order by u.created_at
  loop
    perform public.create_profile(r.id, r.email, r.raw_user_meta_data);
  end loop;
end;
$$;

-- Hilfsfunktionen sind nicht von außen aufrufbar
revoke all on function public.gen_user_code() from public, anon, authenticated;
revoke all on function public.create_profile(uuid, text, jsonb) from public, anon, authenticated;
revoke all on function public.handle_new_user() from public, anon, authenticated;

-- Zugriff: nur das eigene Profil lesen; nur den Namen ändern (ID bleibt fest)
alter table public.profiles enable row level security;

drop policy if exists "profil lesen" on public.profiles;
drop policy if exists "profil aendern" on public.profiles;

create policy "profil lesen" on public.profiles
  for select to authenticated
  using (id = auth.uid());

create policy "profil aendern" on public.profiles
  for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (username) on public.profiles to authenticated;

-- 4) Kalender: Termine (jeder sieht und ändert nur seine eigenen)
create table if not exists public.appointments (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users (id) on delete cascade,
  title      text not null check (char_length(title) between 1 and 80),
  day        date not null,
  at_time    time not null default '09:00',
  done       boolean not null default false,
  notified   boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists appointments_user_day on public.appointments (user_id, day);

alter table public.appointments enable row level security;
drop policy if exists "termine eigene" on public.appointments;
create policy "termine eigene" on public.appointments
  for all to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

revoke all on public.appointments from anon;
grant select, insert, update, delete on public.appointments to authenticated;
