CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;
 
CREATE TABLE users (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                 UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    email                   VARCHAR(255) UNIQUE NOT NULL,
    password_hash           VARCHAR(255),
    auth_provider           VARCHAR(20) NOT NULL DEFAULT 'email'
                                CHECK (auth_provider IN ('email', 'google')),
    google_id               VARCHAR(255) UNIQUE,
    first_name              VARCHAR(100),
    last_name               VARCHAR(100),
    phone_number            VARCHAR(20),
    account_type            VARCHAR(20) NOT NULL DEFAULT 'customer'
                                CHECK (account_type IN ('customer', 'print_house', 'both')),
    is_email_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    profile_completed       BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_attempts   INTEGER NOT NULL DEFAULT 0,
    locked_until            TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);