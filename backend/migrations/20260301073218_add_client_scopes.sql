-- +goose Up
-- +goose StatementBegin
ALTER TABLE clients
ADD COLUMN scopes TEXT[];
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE clients
DROP COLUMN scopes;
-- +goose StatementEnd
