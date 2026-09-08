-- +goose Up
-- Runtime receipt updates name state even when the machine remains online.
-- Fence relay grants only when one of the monitored authority values changes.
DROP TRIGGER machine_peer_network_generation ON user_machines;
CREATE TRIGGER machine_peer_network_generation
AFTER UPDATE OF state, seat_state, revoked_at, deleted_at, installation_generation ON user_machines
FOR EACH ROW
WHEN (ROW(OLD.state, OLD.seat_state, OLD.revoked_at, OLD.deleted_at, OLD.installation_generation)
 IS DISTINCT FROM ROW(NEW.state, NEW.seat_state, NEW.revoked_at, NEW.deleted_at, NEW.installation_generation))
EXECUTE FUNCTION advance_peer_network_for_machine();

-- +goose Down
DROP TRIGGER machine_peer_network_generation ON user_machines;
CREATE TRIGGER machine_peer_network_generation
AFTER UPDATE OF state, seat_state, revoked_at, deleted_at, installation_generation ON user_machines
FOR EACH ROW EXECUTE FUNCTION advance_peer_network_for_machine();
