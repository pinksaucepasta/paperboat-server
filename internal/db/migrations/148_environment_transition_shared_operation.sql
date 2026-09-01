-- +goose Up

-- Every scope manifest staged by one atomic ENV authority transition is bound
-- to the transition's single operation ID. Scope identity is already unique by
-- the primary key (transition_id, scope_ref), so operation_id must not be
-- unique within a multi-scope transition.
ALTER TABLE environment_transition_manifests
  DROP CONSTRAINT IF EXISTS environment_transition_manifests_transition_id_operation_id_key;

-- +goose Down
-- Intentionally irreversible: restoring the invalid uniqueness constraint
-- would reject valid global plus machine atomic transitions.
