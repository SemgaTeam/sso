-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users(
  id CHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name VARCHAR(20) NOT NULL,
  email VARCHAR(63) NOT NULL UNIQUE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE users;
DROP EXTENSION pgcrypto;
-- +goose StatementEnd
