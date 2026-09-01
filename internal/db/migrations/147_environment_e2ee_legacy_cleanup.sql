-- +goose Up

-- Migration 143 used a column-name probe while replacing an unreleased,
-- server-decryptable ENV design. Some development databases can have the
-- legacy tables with a different column name or only a subset of the tables.
-- Remove every legacy table by identity, without selecting or transforming
-- any stored value. The current E2EE schema uses environment_* tables without
-- the environment_variable_* names below.
DROP TABLE IF EXISTS environment_variable_observations;
DROP TABLE IF EXISTS environment_variables;
DROP TABLE IF EXISTS environment_variable_scopes;

-- +goose Down
-- Irreversible: the removed legacy schema was intentionally server-decryptable
-- and must not be recreated.
