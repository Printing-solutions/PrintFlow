
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

COMMENT ON TABLE otp_verifications IS
    'Stores generated OTPs for email verification during registration and MFA login.';
COMMENT ON COLUMN otp_verifications.purpose IS
    'registration = account creation OTP, mfa = login MFA OTP, mfa_setup = enabling MFA.';
COMMENT ON COLUMN otp_verifications.attempt_count IS
    'Number of failed verification attempts. At 5, user must resend. At 10, session expires.';
COMMENT ON COLUMN otp_verifications.resend_count IS
    'Number of times OTP has been resent. Max 5 resends per session.';
COMMENT ON COLUMN otp_verifications.resend_blocked_until IS
    'After 5 resends, resend is blocked until this timestamp (30 minutes).';
COMMENT ON COLUMN otp_verifications.expires_at IS
    'Registration OTP expires after 5 minutes. MFA OTP expires after 10 minutes.';


CREATE TABLE password_reset_tokens (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_id    UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(user_id),
    token       VARCHAR(255) UNIQUE NOT NULL,
    is_used     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP NOT NULL
);

COMMENT ON TABLE password_reset_tokens IS
    'Secure tokens for password reset. Each token expires after 15 minutes and is single-use.';


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

COMMENT ON TABLE user_sessions IS
    'Active login sessions. Each successful login creates a session record.';
COMMENT ON COLUMN user_sessions.session_token IS
    'Cryptographically secure random token issued to the client on login.';