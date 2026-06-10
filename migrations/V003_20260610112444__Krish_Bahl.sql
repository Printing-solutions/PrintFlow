
-- DB-1: sp_check_email_exists
-- Uses a SELECT on users table to check if email is registered.

DROP FUNCTION IF EXISTS sp_check_email_exists(VARCHAR);
DROP FUNCTION IF EXISTS sp_create_user_email(VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS sp_create_user_google(VARCHAR, VARCHAR, VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS sp_generate_otp(VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS sp_verify_otp(VARCHAR, VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS sp_activate_account(VARCHAR);
DROP FUNCTION IF EXISTS sp_validate_login(VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS sp_record_failed_login(UUID);
DROP FUNCTION IF EXISTS sp_clear_failed_logins(UUID);
DROP FUNCTION IF EXISTS sp_create_session(UUID, VARCHAR, TEXT, VARCHAR);
DROP FUNCTION IF EXISTS sp_generate_reset_token(VARCHAR);
DROP FUNCTION IF EXISTS sp_validate_reset_token(VARCHAR);
DROP FUNCTION IF EXISTS sp_reset_password(VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS sp_change_password(UUID, VARCHAR, VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS sp_update_profile(UUID, VARCHAR, VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS sp_set_account_role(UUID, VARCHAR);
DROP FUNCTION IF EXISTS sp_set_mfa_status(UUID, BOOLEAN);
DROP FUNCTION IF EXISTS sp_get_google_user(VARCHAR);



CREATE OR REPLACE FUNCTION sp_check_email_exists(
    log_email VARCHAR(255)
)
RETURNS TABLE(
    email_exists    BOOLEAN,
    auth_provider   VARCHAR(20),
    message         text
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    SELECT
        TRUE,
        u.auth_provider
    FROM users u
    WHERE u.email     = LOWER(TRIM(log_email))
      AND u.is_active = TRUE;

    IF NOT FOUND THEN
        RETURN QUERY 
        SELECT 
            FALSE, 
            NULL::VARCHAR(20),
            'email not available'::text;
    END IF;
END;
$$;



-- DB-2: sp_create_user_email
-- Checks users table for duplicate email, then inserts new row.

CREATE OR REPLACE FUNCTION sp_create_user_email(
    log_email         VARCHAR(255),
    log_password_hash VARCHAR(255)
)
RETURNS TABLE(
    status   VARCHAR(20),
    message  TEXT,
    user_id  UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    auser_id UUID;
BEGIN
    -- Check duplicate using SELECT on users table
    IF EXISTS (
        SELECT 1 FROM users
        WHERE email = LOWER(TRIM(log_email))
    ) THEN
        RETURN QUERY SELECT
            'ERROR'::VARCHAR(20),
            'An account with this email address already exists. Please log in instead.'::TEXT,
            NULL::UUID;
        RETURN;
    END IF;

    INSERT INTO users (
        email, password_hash, auth_provider,
        is_email_verified, is_active, account_type
    ) VALUES (
        LOWER(TRIM(log_email)), log_password_hash, 'email',
        FALSE, TRUE, 'customer'
    )
    RETURNING users.user_id INTO auser_id;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'Account created. OTP sent for verification.'::TEXT,
        auser_id;
END;
$$;



-- DB-3: sp_create_user_google
-- Checks users table for email/google_id conflicts, then inserts.

CREATE OR REPLACE FUNCTION sp_create_user_google(
    p_email      VARCHAR(255),
    p_google_id  VARCHAR(255),
    p_first_name VARCHAR(100),
    p_last_name  VARCHAR(100)
)
RETURNS TABLE(
    status   VARCHAR(20),
    message  TEXT,
    user_id  UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id UUID;
BEGIN
    -- Check if email exists as a password account using SELECT on users
    IF EXISTS (
        SELECT 1 FROM users
        WHERE email         = LOWER(TRIM(p_email))
          AND auth_provider = 'email'
    ) THEN
        RETURN QUERY SELECT
            'CONFLICT'::VARCHAR(20),
            'An account with this email already exists. Please log in with your email and password instead.'::TEXT,
            NULL::UUID;
        RETURN;
    END IF;

    -- Check if Google account already exists using SELECT on users
    IF EXISTS (
        SELECT 1 FROM users
        WHERE email         = LOWER(TRIM(p_email))
          AND auth_provider = 'google'
    ) THEN
        RETURN QUERY SELECT
            'CONFLICT'::VARCHAR(20),
            'This email is already registered using google'::TEXT,
            NULL::UUID;
        RETURN;
    END IF;

    -- Create new Google user
    INSERT INTO users (
        email, google_id, auth_provider,
        first_name, last_name,
        is_email_verified, is_active, account_type
    ) VALUES (
        LOWER(TRIM(p_email)), p_google_id, 'google',
        TRIM(p_first_name), TRIM(p_last_name),
        TRUE, TRUE, 'customer'
    )
    RETURNING users.user_id INTO v_user_id;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'Google account created successfully.'::TEXT,
        v_user_id;
END;
$$;



-- DB-4: sp_generate_otp
-- Reads otp_verifications to check resend count, then inserts
-- a new OTP row. Invalidates old OTPs using UPDATE.

CREATE OR REPLACE FUNCTION sp_generate_otp(
    p_email   VARCHAR(255),
    p_purpose VARCHAR(20)
)
RETURNS TABLE(
    status     VARCHAR(20),
    message    TEXT,
    otp_code   VARCHAR(6),
    expires_at TIMESTAMP
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_otp            VARCHAR(6);
    v_expires        TIMESTAMP;
    v_resend_count   INTEGER;
    v_blocked_until  TIMESTAMP;
BEGIN
    -- Read current resend state from otp_verifications table
    SELECT resend_count, resend_blocked_until
    INTO   v_resend_count, v_blocked_until
    FROM   otp_verifications
    WHERE  email   = LOWER(TRIM(p_email))
      AND  purpose = p_purpose
      AND  is_used = FALSE
    ORDER BY created_at DESC
    LIMIT 1;

    -- If resend is blocked, return early
    IF v_blocked_until IS NOT NULL
       AND v_blocked_until > CURRENT_TIMESTAMP THEN
        RETURN QUERY SELECT
            'BLOCKED'::VARCHAR(20),
            'You have requested too many codes. Please try again after 30 minutes.'::TEXT,
            NULL::VARCHAR(6),
            v_blocked_until;
        RETURN;
    END IF;

    -- Invalidate all previous active OTPs using UPDATE on otp_verifications
    UPDATE otp_verifications
    SET    is_used = TRUE
    WHERE  email   = LOWER(TRIM(p_email))
      AND  purpose = p_purpose
      AND  is_used = FALSE;

    -- Generate 6-digit OTP
    v_otp     := LPAD(FLOOR(RANDOM() * 1000000)::TEXT, 6, '0');

    -- Expiry: 5 min for registration, 10 min for MFA
    v_expires := CASE
        WHEN p_purpose = 'registration'
        THEN CURRENT_TIMESTAMP + INTERVAL '5 minutes'
        ELSE CURRENT_TIMESTAMP + INTERVAL '10 minutes'
    END;

    v_resend_count := COALESCE(v_resend_count, 0) + 1;

    -- Insert new OTP row into otp_verifications
    INSERT INTO otp_verifications (
        email, otp_code, purpose,
        resend_count, resend_blocked_until, expires_at
    ) VALUES (
        LOWER(TRIM(p_email)),
        v_otp,
        p_purpose,
        v_resend_count,
        CASE WHEN v_resend_count >= 5
             THEN CURRENT_TIMESTAMP + INTERVAL '30 minutes'
             ELSE NULL
        END,
        v_expires
    );

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'OTP generated and sent.'::TEXT,
        v_otp,
        v_expires;
END;
$$;



-- DB-5: sp_verify_otp
-- Reads otp_verifications using SELECT, checks all conditions,
-- then updates attempt_count or marks is_used = TRUE.

CREATE OR REPLACE FUNCTION sp_verify_otp(
    p_email    VARCHAR(255),
    p_otp_code VARCHAR(6),
    p_purpose  VARCHAR(20)
)
RETURNS TABLE(
    status  VARCHAR(20),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_rec otp_verifications%ROWTYPE;
BEGIN
    -- Read latest active OTP from otp_verifications
    SELECT * INTO v_rec
    FROM   otp_verifications
    WHERE  email   = LOWER(TRIM(p_email))
      AND  purpose = p_purpose
      AND  is_used = FALSE
    ORDER BY created_at DESC
    LIMIT 1;

    IF v_rec IS NULL THEN
        RETURN QUERY SELECT
            'NOT_FOUND'::VARCHAR(20),
            'No active OTP found, request a new one'::TEXT;
        RETURN;
    END IF;

    -- Check expiry
    IF v_rec.expires_at < CURRENT_TIMESTAMP THEN
        UPDATE otp_verifications
        SET    is_used = TRUE
        WHERE  otp_id = v_rec.otp_id;

        RETURN QUERY SELECT
            'EXPIRED'::VARCHAR(20),
            'This code has expired. Please request a new one.'::TEXT;
        RETURN;
    END IF;

    -- 10 failed attempts = session expires
    IF v_rec.attempt_count >= 10 THEN
        UPDATE otp_verifications
        SET    is_used = TRUE
        WHERE  otp_id = v_rec.otp_id;

        RETURN QUERY SELECT
            'SESSION_EXPIRED'::VARCHAR(20),
            'Too many failed attempts. Your session has expired. Please start again.'::TEXT;
        RETURN;
    END IF;

    -- 5 failed attempts = must resend
    IF v_rec.attempt_count >= 5 THEN
        RETURN QUERY SELECT
            'RESEND_REQUIRED'::VARCHAR(20),
            'Too many incorrect attempts. Please request a new code.'::TEXT;
        RETURN;
    END IF;

    -- Wrong OTP — increment attempt_count on otp_verifications
    IF v_rec.otp_code != p_otp_code THEN
        UPDATE otp_verifications
        SET    attempt_count = attempt_count + 1
        WHERE  otp_id = v_rec.otp_id;

        RETURN QUERY SELECT
            'INVALID'::VARCHAR(20),
            'Incorrect verification code. Please try again.'::TEXT;
        RETURN;
    END IF;

    -- Correct — mark OTP as used
    UPDATE otp_verifications
    SET    is_used = TRUE
    WHERE  otp_id = v_rec.otp_id;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'Verification successful.'::TEXT;
END;
$$;



-- Helper: sp_activate_account
-- Called after OTP verified. Updates is_email_verified on users.

CREATE OR REPLACE FUNCTION sp_activate_account(
    p_email VARCHAR(255)
)
RETURNS TABLE(
    status  VARCHAR(20),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Simple UPDATE on users table
    UPDATE users
    SET    is_email_verified = TRUE,
           updated_at        = CURRENT_TIMESTAMP
    WHERE  email     = LOWER(TRIM(p_email))
      AND  is_active = TRUE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'NOT_FOUND'::VARCHAR(20),
            'Account not found.'::TEXT;
        RETURN;
    END IF;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'Account verified'::TEXT;
END;
$$;



-- DB-6: sp_validate_login
-- SELECT on users to check email, verification, lockout,
-- and password hash match.

CREATE OR REPLACE FUNCTION sp_validate_login(
    p_email         VARCHAR(255),
    p_password_hash VARCHAR(255)
)
RETURNS TABLE(
    status      VARCHAR(20),
    message     TEXT,
    user_id     UUID,
    mfa_enabled BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user users%ROWTYPE;
BEGIN
    -- Read user row from users table
    SELECT * INTO v_user
    FROM   users
    WHERE  email         = LOWER(TRIM(p_email))
      AND  auth_provider = 'email'
      AND  is_active     = TRUE;

    -- Email not found
    IF v_user IS NULL THEN
        RETURN QUERY SELECT
            'INVALID'::VARCHAR(20),
            'Incorrect email address or password.'::TEXT,
            NULL::UUID, FALSE;
        RETURN;
    END IF;

    -- Account not verified
    IF NOT v_user.is_email_verified THEN
        RETURN QUERY SELECT
            'UNVERIFIED'::VARCHAR(20),
            'Please verify your email address before logging in.'::TEXT,
            NULL::UUID, FALSE;
        RETURN;
    END IF;

    -- Account locked — check locked_until column on users
    IF v_user.locked_until IS NOT NULL
       AND v_user.locked_until > CURRENT_TIMESTAMP THEN
        RETURN QUERY SELECT
            'LOCKED'::VARCHAR(20),
            'Your account has been temporarily locked due to multiple failed login attempts. Please try again after 30 minutes or reset your password.'::TEXT,
            NULL::UUID, FALSE;
        RETURN;
    END IF;

    -- Wrong password
    IF v_user.password_hash <> p_password_hash THEN
        PERFORM sp_record_failed_login(v_user.user_id);
        RETURN QUERY SELECT
            'INVALID'::VARCHAR(20),
            'Incorrect email address or password.'::TEXT,
            NULL::UUID, FALSE;
        RETURN;
    END IF;

    -- Success
    PERFORM sp_clear_failed_logins(v_user.user_id);

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'Login successful.'::TEXT,
        v_user.user_id,
        v_user.mfa_enabled;
END;
$$;


-- ------------------------------------------------------------
-- DB-7: sp_record_failed_login
-- UPDATE on users table to increment failed_login_attempts.
-- Sets locked_until if attempts reach 5.
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION sp_record_failed_login(
    p_user_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE users
    SET
        failed_login_attempts = failed_login_attempts + 1,
        locked_until = CASE
            WHEN failed_login_attempts + 1 >= 5
            THEN CURRENT_TIMESTAMP + INTERVAL '30 minutes'
            ELSE locked_until
        END,
        updated_at = CURRENT_TIMESTAMP
    WHERE user_id = p_user_id;
END;
$$;



-- DB-8: sp_clear_failed_logins
-- UPDATE on users to reset failed_login_attempts and locked_until.

CREATE OR REPLACE FUNCTION sp_clear_failed_logins(
    p_user_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE users
    SET
        failed_login_attempts = 0,
        locked_until          = NULL,
        updated_at            = CURRENT_TIMESTAMP
    WHERE user_id = p_user_id;
END;
$$;



-- DB-9: sp_create_session
-- INSERT into user_sessions table.

CREATE OR REPLACE FUNCTION sp_create_session(
    p_user_id       UUID,
    p_session_token VARCHAR(512),
    p_device_info   TEXT,
    p_ip_address    VARCHAR(45)
)
RETURNS TABLE(
    status     VARCHAR(20),
    session_id UUID,
    expires_at TIMESTAMP
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_session_id UUID;
    v_expires    TIMESTAMP;
BEGIN
    v_expires := CURRENT_TIMESTAMP + INTERVAL '24 hours';

    INSERT INTO user_sessions (
        user_id, session_token,
        device_info, ip_address, expires_at
    ) VALUES (
        p_user_id, p_session_token,
        p_device_info, p_ip_address, v_expires
    )
    RETURNING user_sessions.session_id INTO v_session_id;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        v_session_id,
        v_expires;
END;
$$;



-- DB-10: sp_generate_reset_token
-- SELECT on users to find user, then INSERT into
-- password_reset_tokens. Previous tokens invalidated via UPDATE.

CREATE OR REPLACE FUNCTION sp_generate_reset_token(
    p_email VARCHAR(255)
)
RETURNS TABLE(
    status     VARCHAR(20),
    message    TEXT,
    token      VARCHAR(255),
    expires_at TIMESTAMP
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id UUID;
    v_token   VARCHAR(255);
    v_expires TIMESTAMP;
BEGIN
    -- Find user using SELECT on users table
    SELECT user_id INTO v_user_id
    FROM   users
    WHERE  email         = LOWER(TRIM(p_email))
      AND  auth_provider = 'email'
      AND  is_active     = TRUE;

    -- Return same message whether email exists or not (prevents enumeration)
    IF v_user_id IS NULL THEN
        RETURN QUERY SELECT
            'NOT_FOUND'::VARCHAR(20),
            'If an account with this email exists, a password reset link has been sent.'::TEXT,
            NULL::VARCHAR(255),
            NULL::TIMESTAMP;
        RETURN;
    END IF;

    -- Invalidate old tokens via UPDATE on password_reset_tokens
    UPDATE password_reset_tokens
    SET    is_used = TRUE
    WHERE  user_id = v_user_id AND is_used = FALSE;

    -- Generate secure token
    v_token   := encode(gen_random_bytes(32), 'hex');
    v_expires := CURRENT_TIMESTAMP + INTERVAL '15 minutes';

    -- INSERT new token into password_reset_tokens
    INSERT INTO password_reset_tokens (user_id, token, expires_at)
    VALUES (v_user_id, v_token, v_expires);

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'If an account with this email exists, a password reset link has been sent.'::TEXT,
        v_token,
        v_expires;
END;
$$;



-- DB-11: sp_validate_reset_token
-- SELECT on password_reset_tokens to check token validity.

CREATE OR REPLACE FUNCTION sp_validate_reset_token(
    p_token VARCHAR(255)
)
RETURNS TABLE(
    status  VARCHAR(20),
    message TEXT,
    user_id UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_rec password_reset_tokens%ROWTYPE;
BEGIN
    -- Read token row from password_reset_tokens
    SELECT * INTO v_rec
    FROM   password_reset_tokens
    WHERE  token = p_token;

    IF v_rec IS NULL THEN
        RETURN QUERY SELECT
            'INVALID'::VARCHAR(20),
            'Invalid reset link.'::TEXT,
            NULL::UUID;
        RETURN;
    END IF;

    IF v_rec.is_used THEN
        RETURN QUERY SELECT
            'USED'::VARCHAR(20),
            'This reset link has already been used. Please request a new one.'::TEXT,
            NULL::UUID;
        RETURN;
    END IF;

    IF v_rec.expires_at < CURRENT_TIMESTAMP THEN
        RETURN QUERY SELECT
            'EXPIRED'::VARCHAR(20),
            'This password reset link has expired. Please request a new one.'::TEXT,
            NULL::UUID;
        RETURN;
    END IF;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'Token is valid.'::TEXT,
        v_rec.user_id;
END;
$$;



-- DB-12: sp_reset_password
-- Calls sp_validate_reset_token, then UPDATE on users for
-- new password, UPDATE on password_reset_tokens to mark used,
-- UPDATE on user_sessions to kill all sessions.

CREATE OR REPLACE FUNCTION sp_reset_password(
    p_token             VARCHAR(255),
    p_new_password_hash VARCHAR(255)
)
RETURNS TABLE(
    status  VARCHAR(20),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id      UUID;
    v_token_status VARCHAR(20);
    v_token_msg    TEXT;
    v_current_hash VARCHAR(255);
BEGIN
    -- Validate token using sp_validate_reset_token
    SELECT status, message, user_id
    INTO   v_token_status, v_token_msg, v_user_id
    FROM   sp_validate_reset_token(p_token);

    IF v_token_status <> 'SUCCESS' THEN
        RETURN QUERY SELECT v_token_status, v_token_msg;
        RETURN;
    END IF;

    -- Read current password from users table
    SELECT password_hash INTO v_current_hash
    FROM   users
    WHERE  user_id = v_user_id;

    -- Block same password
    IF v_current_hash IS NOT NULL
       AND v_current_hash = p_new_password_hash THEN
        RETURN QUERY SELECT
            'SAME_PASSWORD'::VARCHAR(20),
            'Your new password must be different from your current password.'::TEXT;
        RETURN;
    END IF;

    -- UPDATE users with new password
    UPDATE users
    SET    password_hash = p_new_password_hash,
           updated_at    = CURRENT_TIMESTAMP
    WHERE  user_id = v_user_id;

    -- UPDATE password_reset_tokens to mark token as used
    UPDATE password_reset_tokens
    SET    is_used = TRUE
    WHERE  token = p_token;

    -- Clear lockout via UPDATE on users
    PERFORM sp_clear_failed_logins(v_user_id);

    -- Kill all sessions via UPDATE on user_sessions
    UPDATE user_sessions
    SET    is_active = FALSE
    WHERE  user_id   = v_user_id
      AND  is_active = TRUE;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'Your password has been reset successfully. Please log in with your new password.'::TEXT;
END;
$$;



-- DB-13: sp_change_password
-- SELECT on users to verify current password, then UPDATE
-- users with new password, UPDATE user_sessions to kill
-- all sessions except the current one.

CREATE OR REPLACE FUNCTION sp_change_password(
    p_user_id               UUID,
    p_current_password_hash VARCHAR(255),
    p_new_password_hash     VARCHAR(255),
    p_current_session_token VARCHAR(512)
)
RETURNS TABLE(
    status  VARCHAR(20),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_stored_hash VARCHAR(255);
BEGIN
    -- Read current password from users table
    SELECT password_hash INTO v_stored_hash
    FROM   users
    WHERE  user_id   = p_user_id
      AND  is_active = TRUE;

    IF v_stored_hash IS NULL THEN
        RETURN QUERY SELECT
            'NOT_FOUND'::VARCHAR(20),
            'Account not found.'::TEXT;
        RETURN;
    END IF;

    -- Verify current password matches
    IF v_stored_hash <> p_current_password_hash THEN
        RETURN QUERY SELECT
            'INVALID'::VARCHAR(20),
            'Your current password is incorrect.'::TEXT;
        RETURN;
    END IF;

    -- Block same password
    IF v_stored_hash = p_new_password_hash THEN
        RETURN QUERY SELECT
            'SAME_PASSWORD'::VARCHAR(20),
            'Your new password must be different from your current password.'::TEXT;
        RETURN;
    END IF;

    -- UPDATE users with new password
    UPDATE users
    SET    password_hash = p_new_password_hash,
           updated_at    = CURRENT_TIMESTAMP
    WHERE  user_id = p_user_id;

    -- UPDATE user_sessions — kill all except current session
    UPDATE user_sessions
    SET    is_active = FALSE
    WHERE  user_id        = p_user_id
      AND  session_token <> p_current_session_token
      AND  is_active      = TRUE;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'Your password has been updated successfully.'::TEXT;
END;
$$;



-- DB-14: sp_update_profile
-- UPDATE on users table with first name, last name, phone.

CREATE OR REPLACE FUNCTION sp_update_profile(
    p_user_id      UUID,
    p_first_name   VARCHAR(100),
    p_last_name    VARCHAR(100),
    p_phone_number VARCHAR(20)
)
RETURNS TABLE(
    status  VARCHAR(20),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE users
    SET    first_name        = TRIM(p_first_name),
           last_name         = TRIM(p_last_name),
           phone_number      = TRIM(p_phone_number),
           profile_completed = TRUE,
           updated_at        = CURRENT_TIMESTAMP
    WHERE  user_id   = p_user_id
      AND  is_active = TRUE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'NOT_FOUND'::VARCHAR(20),
            'Account not found.'::TEXT;
        RETURN;
    END IF;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        'Profile updated successfully.'::TEXT;
END;
$$;



-- DB-15: sp_set_account_role
-- UPDATE on users table to set account_type.

CREATE OR REPLACE FUNCTION sp_set_account_role(
    p_user_id      UUID,
    p_account_type VARCHAR(20)
)
RETURNS TABLE(
    status  VARCHAR(20),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF p_account_type NOT IN ('customer', 'print_house', 'both') THEN
        RETURN QUERY SELECT
            'INVALID'::VARCHAR(20),
            'Invalid account type specified.'::TEXT;
        RETURN;
    END IF;

    UPDATE users
    SET    account_type = p_account_type,
           updated_at   = CURRENT_TIMESTAMP
    WHERE  user_id   = p_user_id
      AND  is_active = TRUE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'NOT_FOUND'::VARCHAR(20),
            'Account not found.'::TEXT;
        RETURN;
    END IF;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        ('Account role updated to: ' || p_account_type || '.')::TEXT;
END;
$$;



-- DB-16: sp_set_mfa_status
-- UPDATE on users table to toggle mfa_enabled.

CREATE OR REPLACE FUNCTION sp_set_mfa_status(
    p_user_id UUID,
    p_enabled BOOLEAN
)
RETURNS TABLE(
    status  VARCHAR(20),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE users
    SET    mfa_enabled = p_enabled,
           updated_at  = CURRENT_TIMESTAMP
    WHERE  user_id   = p_user_id
      AND  is_active = TRUE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'NOT_FOUND'::VARCHAR(20),
            'Account not found.'::TEXT;
        RETURN;
    END IF;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR(20),
        CASE WHEN p_enabled
             THEN 'Two-factor authentication has been enabled.'
             ELSE 'Two-factor authentication has been disabled.'
        END::TEXT;
END;
$$;



-- DB-17: sp_get_google_user
-- SELECT on users table using google_id to find the user.

CREATE OR REPLACE FUNCTION sp_get_google_user(
    p_google_id VARCHAR(255)
)
RETURNS TABLE(
    status            VARCHAR(20),
    message           TEXT,
    user_id           UUID,
    email             VARCHAR(255),
    account_type      VARCHAR(20),
    profile_completed BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    SELECT
        'SUCCESS'::VARCHAR(20),
        'Google user found.'::TEXT,
        u.user_id,
        u.email,
        u.account_type,
        u.profile_completed
    FROM users u
    WHERE u.google_id = p_google_id
      AND u.is_active = TRUE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'NOT_FOUND'::VARCHAR(20),
            'No account linked to this Google ID.'::TEXT,
            NULL::UUID,
            NULL::VARCHAR(255),
            NULL::VARCHAR(20),
            NULL::BOOLEAN;
    END IF;
END;
$$;