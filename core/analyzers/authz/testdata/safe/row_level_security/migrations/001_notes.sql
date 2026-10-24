CREATE TABLE notes (id uuid primary key, owner uuid not null, body text);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_owner ON notes USING (owner = current_setting('app.user_id')::uuid);
