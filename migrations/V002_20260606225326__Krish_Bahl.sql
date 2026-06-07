CREATE TABLE otp_verifications (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    otp_id          UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    email           VARCHAR(255) NOT NULL,
    otp_code        VARCHAR(6) NOT NULL,
    purpose         VARCHAR(20) NOT NULL
                        CHECK (purpose IN ('registration', 'mfa', 'mfa_setup')),
    is_used         BOOLEAN NOT NULL DEFAULT FALSE,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    resend_count    INTEGER NOT NULL DEFAULT 0,
    resend_blocked_until TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP NOT NULL
);
 

CREATE TABLE password_reset_tokens (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_id    UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(user_id),
    token       VARCHAR(255) UNIQUE NOT NULL,
    is_used     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP NOT NULL
);
 

    
CREATE TABLE user_sessions (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id      UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(user_id),
    session_token   VARCHAR(512) UNIQUE NOT NULL,
    device_info     TEXT,
    ip_address      VARCHAR(45),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP NOT NULL,
    last_active_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);