-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email VARCHAR(254) UNIQUE NOT NULL,
  name VARCHAR(255),
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);  
  
CREATE TABLE identities (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  external_id VARCHAR(255),
  issuer VARCHAR(255),
  attributes JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, type, external_id)
);

CREATE TABLE credentials (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  secret_hash TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMP,
  expires_at TIMESTAMP,
  status VARCHAR(20) NOT NULL DEFAULT 'active'
);

CREATE TABLE clients (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL UNIQUE,
  client_secret TEXT,
  is_confidential BOOLEAN NOT NULL DEFAULT TRUE,
  redirect_uris TEXT[], -- array of allowed redirect URIs
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  ip VARCHAR(50),
  user_agent TEXT,
  revoked_at TIMESTAMP
);

CREATE TABLE tokens (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  subject_user_id UUID NOT NULL REFERENCES users(id),
  client_id UUID NOT NULL REFERENCES clients(id),
  token TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  is_revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE scopes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) UNIQUE NOT NULL,
  description TEXT
);

CREATE TABLE client_scopes (
  client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  scope_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  PRIMARY KEY(client_id, scope_id)
);

CREATE TABLE consents (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  scopes TEXT[] NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  PRIMARY KEY(user_id, client_id)
);

CREATE TABLE audit_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  type VARCHAR(50) NOT NULL,    
  user_id UUID NOT NULL REFERENCES users(id),
  client_id UUID NOT NULL REFERENCES clients(id),
  ip VARCHAR(50),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  metadata JSONB
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE audit_events;
DROP TABLE consents;
DROP TABLE client_scopes;
DROP TABLE scopes;
DROP TABLE tokens;
DROP TABLE sessions;
DROP TABLE clients;
DROP TABLE credentials;
DROP TABLE identities;
DROP TABLE users;
-- +goose StatementEnd
