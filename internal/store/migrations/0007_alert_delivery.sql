-- What happened to a rule's last mail.
--
-- Its own migration rather than two more columns in 0006, even though the two shipped in the same
-- branch and no release has seen either. The runner records a migration by name and never re-reads
-- it, so editing an applied file changes nothing on a database that already has it: anybody who
-- tested an earlier commit of that branch would get a schema silently missing these columns, and
-- would find out through a query error rather than through a migration. A migration is append-only
-- from the moment it can have run anywhere, which is the moment it is pushed.
--
-- The columns exist because an alert that never went out and an alert that never fired are
-- indistinguishable from an inbox. The event itself is in the inbox either way; this is the record
-- of the delivery that did not happen, on the row an operator is already looking at.
ALTER TABLE alert_rules
    ADD COLUMN IF NOT EXISTS last_delivery_at    timestamptz,
    ADD COLUMN IF NOT EXISTS last_delivery_error text NOT NULL DEFAULT '';
