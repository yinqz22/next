-- next: einmalig im Supabase SQL Editor ausführen (Dashboard -> SQL Editor -> New query).
-- Ohne dieses Skript funktionieren Profilbild-Upload und "Konto löschen" nicht.
-- Name, Theme, Sprache und Sichtbarkeit brauchen es NICHT (die liegen in den User-Metadaten).

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
