CREATE INDEX controller_audit_action_time ON controller_audit (action,created_at,id);
CREATE INDEX controller_audit_actor_time ON controller_audit (actor,created_at,id);
CREATE INDEX controller_audit_target_time ON controller_audit (target,created_at,id);
CREATE INDEX controller_identity_audit_action_time ON controller_identity_audit (action,created_at,id);
CREATE INDEX controller_identity_audit_actor_time ON controller_identity_audit (actor,created_at,id);
CREATE INDEX controller_identity_audit_target_time ON controller_identity_audit (target,created_at,id);
