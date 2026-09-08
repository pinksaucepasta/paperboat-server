-- +goose Up
ALTER TABLE browser_access_transactions DROP CONSTRAINT browser_access_transactions_resource_kind_check;
ALTER TABLE browser_access_transactions ADD CONSTRAINT browser_access_transactions_resource_kind_check CHECK(resource_kind IN ('preview','tunnel','lazy_policy'));
ALTER TABLE browser_access_sessions DROP CONSTRAINT browser_access_sessions_resource_kind_check;
ALTER TABLE browser_access_sessions ADD CONSTRAINT browser_access_sessions_resource_kind_check CHECK(resource_kind IN ('preview','tunnel','lazy_policy'));
ALTER TABLE browser_machine_credentials DROP CONSTRAINT browser_machine_credentials_resource_kind_check;
ALTER TABLE browser_machine_credentials ADD CONSTRAINT browser_machine_credentials_resource_kind_check CHECK(resource_kind IN ('preview','tunnel','lazy_policy'));
ALTER TABLE team_resource_bindings DROP CONSTRAINT team_resource_bindings_resource_kind_check;
ALTER TABLE team_resource_bindings ADD CONSTRAINT team_resource_bindings_resource_kind_check CHECK(resource_kind IN ('env','preview','tunnel','lazy_policy'));
ALTER TABLE team_resource_grants DROP CONSTRAINT team_resource_grants_check;
ALTER TABLE team_resource_grants ADD CONSTRAINT team_resource_grants_check CHECK((resource_kind='env' AND permission IN ('read','write')) OR (resource_kind IN ('preview','tunnel','lazy_policy') AND permission IN ('use','manage')));

-- +goose Down
DELETE FROM browser_access_transactions WHERE resource_kind='lazy_policy';
DELETE FROM browser_access_sessions WHERE resource_kind='lazy_policy';
DELETE FROM browser_machine_credentials WHERE resource_kind='lazy_policy';
DELETE FROM team_resource_bindings WHERE resource_kind='lazy_policy';
ALTER TABLE browser_access_transactions DROP CONSTRAINT browser_access_transactions_resource_kind_check;
ALTER TABLE browser_access_transactions ADD CONSTRAINT browser_access_transactions_resource_kind_check CHECK(resource_kind IN ('preview','tunnel'));
ALTER TABLE browser_access_sessions DROP CONSTRAINT browser_access_sessions_resource_kind_check;
ALTER TABLE browser_access_sessions ADD CONSTRAINT browser_access_sessions_resource_kind_check CHECK(resource_kind IN ('preview','tunnel'));
ALTER TABLE browser_machine_credentials DROP CONSTRAINT browser_machine_credentials_resource_kind_check;
ALTER TABLE browser_machine_credentials ADD CONSTRAINT browser_machine_credentials_resource_kind_check CHECK(resource_kind IN ('preview','tunnel'));
ALTER TABLE team_resource_bindings DROP CONSTRAINT team_resource_bindings_resource_kind_check;
ALTER TABLE team_resource_bindings ADD CONSTRAINT team_resource_bindings_resource_kind_check CHECK(resource_kind IN ('env','preview','tunnel'));
ALTER TABLE team_resource_grants DROP CONSTRAINT team_resource_grants_check;
ALTER TABLE team_resource_grants ADD CONSTRAINT team_resource_grants_check CHECK((resource_kind='env' AND permission IN ('read','write')) OR (resource_kind IN ('preview','tunnel') AND permission IN ('use','manage')));
