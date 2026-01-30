-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS identities (
  id CHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  user_id CHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  external_id VARCHAR(255),
  issuer VARCHAR(255),
  attributes JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),

  UNIQUE(user_id, type, issuer)
);

ALTER TABLE credentials
ADD COLUMN identity_id CHAR(36) NOT NULL REFERENCES identities(id) ON DELETE CASCADE;

ALTER TABLE credentials
ADD COLUMN type VARCHAR(50) NOT NULL;

ALTER TABLE credentials
DROP COLUMN user_id;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE credentials
DROP COLUMN identity_id;

ALTER TABLE credentials
DROP COLUMN type;

ALTER TABLE credentials
ADD COLUMN user_id VARCHAR(36) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE;

DROP TABLE identities;
-- +goose StatementEnd
