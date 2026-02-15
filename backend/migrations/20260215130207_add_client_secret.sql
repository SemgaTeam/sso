-- +goose Up
-- +goose StatementBegin
ALTER TABLE clients
ADD column client_secret TEXT NOT NULL UNIQUE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE clients 
DROP column client_secret;
-- +goose StatementEnd
