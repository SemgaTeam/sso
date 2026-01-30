-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS clients (
  id CHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL UNIQUE,
  redirect_uris TEXT[] NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE clients;
-- +goose StatementEnd
