-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS credentials (
  id CHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  user_id VARCHAR(36) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  hash TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  status VARCHAR(20) NOT NULL DEFAULT 'active'
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE credentials;
-- +goose StatementEnd
