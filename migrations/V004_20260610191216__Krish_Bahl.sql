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




CREATE OR REPLACE PROCEDURE email_exists(
    IN  p_email             VARCHAR(255),
    OUT f_email_exists      BOOLEAN,
    OUT f_auth_provider     VARCHAR(20),
    OUT f_message           TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    SELECT
        TRUE,
        u.auth_provider
    INTO
        f_email_exists,
        f_auth_provider
    FROM users u
    WHERE u.email     = LOWER(TRIM(p_email))
      AND u.is_active = TRUE;

    IF f_email_exists IS NULL THEN
        f_email_exists  := FALSE;
        f_auth_provider := NULL;
        f_message       := 'Email not found.';
    ELSE
        f_message := 'Email already registered as ' || f_auth_provider || '.';
    END IF;
END;
$$;





CREATE OR REPLACE PROCEDURE create_user_email(
    IN  p_email         VARCHAR(255),
    IN  p_password_hash VARCHAR(255),
    OUT out_status      VARCHAR(20),
    OUT out_message     TEXT,
    OUT out_user_id     UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM users
        WHERE email = LOWER(TRIM(p_email))
    ) THEN
        out_status  := 'ERROR';
        out_message := 'An account with this email address already exists. Please log in instead.';
        out_user_id := NULL;
        RETURN;
    END IF;

    INSERT INTO users (
        email,
        password_hash,
        auth_provider,
        is_email_verified,
        is_active,
        account_type
    ) VALUES (
        LOWER(TRIM(p_email)),
        p_password_hash,
        'email',
        FALSE,
        TRUE,
        'customer'
    )
    RETURNING users.user_id INTO out_user_id;

    out_status  := 'SUCCESSFUL';
    out_message := 'Account created. OTP sent for verification.';
END;
$$;






CREATE OR REPLACE PROCEDURE create_user_google(
    IN  p_email         VARCHAR(255),
    OUT out_status      VARCHAR(20),
    OUT out_message     TEXT,
    OUT out_user_id     UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM users
        WHERE email = LOWER(TRIM(p_email))
    ) THEN
        out_status  := 'ERROR';
        out_message := 'An account with this email address already exists. Please log in instead.';
        out_user_id := NULL;
        RETURN;
    END IF;

    INSERT INTO users (
        email,
        password_hash,
        auth_provider,
        is_email_verified,
        is_active,
        account_type
    ) VALUES (
        LOWER(TRIM(p_email)),
        NULL,
        'google',
        FALSE,
        TRUE,
        'customer'
    )
    RETURNING users.user_id INTO out_user_id;

    out_status  := 'SUCCESSFUL';
    -- FIX: was 'Please verigy your email.'
    out_message := 'Account created. Please verify your email.';
END;
$$;




CREATE OR REPLACE PROCEDURE generate_otp(
    IN  p_email             VARCHAR(255),
    IN  p_purpose           VARCHAR(20),
    OUT out_status          VARCHAR(20),
    OUT out_message         TEXT,
    OUT out_otp             VARCHAR(6),
    OUT out_expires         TIMESTAMP
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_otp           VARCHAR(6);
    v_expires       TIMESTAMP;
    v_resend_count  INTEGER;
    v_blocked_until TIMESTAMP;
BEGIN
    SELECT resend_count, resend_blocked_until
    INTO   v_resend_count, v_blocked_until
    FROM   otp_verifications
    WHERE  email   = LOWER(TRIM(p_email))
      AND  purpose = p_purpose
      AND  is_used = FALSE
    ORDER BY created_at DESC
    LIMIT 1;

    IF v_blocked_until IS NOT NULL
       AND v_blocked_until > CURRENT_TIMESTAMP THEN
        out_status  := 'BLOCKED';
        out_message := 'You have requested too many codes. Please try again after 30 minutes.';
        out_otp     := NULL;
        out_expires := v_blocked_until;
        RETURN;
    END IF;

    UPDATE otp_verifications
    SET    is_used = TRUE
    WHERE  email   = LOWER(TRIM(p_email))
      AND  purpose = p_purpose
      AND  is_used = FALSE;


    v_otp := LPAD(FLOOR(RANDOM() * 1000000)::TEXT, 6, '0');

    IF p_purpose = 'registration' THEN
        v_expires := CURRENT_TIMESTAMP + INTERVAL '10 minutes';
    ELSE
        v_expires := CURRENT_TIMESTAMP + INTERVAL '5 minutes';
    END IF;


    IF v_resend_count IS NULL THEN
        v_resend_count := 1;
    ELSE
        v_resend_count := v_resend_count + 1;
    END IF;

    INSERT INTO otp_verifications (
        email,
        otp_code,
        purpose,
        resend_count,
        resend_blocked_until,
        expires_at
    ) VALUES (
        LOWER(TRIM(p_email)),
        v_otp,
        p_purpose,
        v_resend_count,
        CASE
            WHEN v_resend_count >= 5
            THEN CURRENT_TIMESTAMP + INTERVAL '30 minutes'
            ELSE NULL
        END,
        v_expires
    );

    out_status  := 'SUCCESS';
    out_message := 'OTP generated and sent.';
    out_otp     := v_otp;
    out_expires := v_expires;
END;
$$;






CREATE OR REPLACE PROCEDURE verify_otp(
    IN  p_email     VARCHAR(255),
    IN  p_otp_code  VARCHAR(6),
    IN  p_purpose   VARCHAR(20),
    OUT out_status  VARCHAR(20),
    OUT out_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_rec otp_verifications%ROWTYPE;
BEGIN
    SELECT * INTO v_rec
    FROM   otp_verifications
    WHERE  email   = LOWER(TRIM(p_email))
      AND  purpose = p_purpose
      AND  is_used = FALSE
    ORDER BY created_at DESC
    LIMIT 1;

    IF v_rec IS NULL THEN
        out_status  := 'NOT_FOUND';
        out_message := 'No active OTP found. Please request a new one.';
        RETURN;
    END IF;

    IF v_rec.expires_at < CURRENT_TIMESTAMP THEN
        UPDATE otp_verifications
        SET    is_used = TRUE
        WHERE  otp_id = v_rec.otp_id;
        out_status  := 'EXPIRED';
        out_message := 'This code has expired. Please request a new one.';
        RETURN;
    END IF;

    IF v_rec.attempt_count >= 10 THEN
        UPDATE otp_verifications
        SET    is_used = TRUE
        WHERE  otp_id = v_rec.otp_id;
        out_status  := 'SESSION_EXPIRED';
        out_message := 'Too many failed attempts. Your session has expired.';
        RETURN;
    END IF;

    IF v_rec.attempt_count >= 5 THEN
        out_status  := 'RESEND_REQUIRED';
        out_message := 'Too many incorrect attempts. Please request a new code.';
        RETURN;
    END IF;

    IF v_rec.otp_code != p_otp_code THEN
        UPDATE otp_verifications
        SET    attempt_count = attempt_count + 1
        WHERE  otp_id = v_rec.otp_id;
        out_status  := 'INVALID';
        out_message := 'Incorrect verification code. Please try again.';
        RETURN;
    END IF;

    UPDATE otp_verifications
    SET    is_used = TRUE
    WHERE  otp_id = v_rec.otp_id;

    out_status  := 'SUCCESS';
    out_message := 'Verification successful.';
END;
$$;





CREATE OR REPLACE PROCEDURE activate_account(
    IN  p_email     VARCHAR(255),
    OUT out_status  VARCHAR(20),
    OUT out_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE users
    SET    is_email_verified = TRUE,
           updated_at        = CURRENT_TIMESTAMP
    WHERE  email     = LOWER(TRIM(p_email))
      AND  is_active = TRUE;

    IF NOT FOUND THEN
        out_status  := 'NOT_FOUND';
        out_message := 'Account not found.';
        RETURN;
    END IF;

    out_status  := 'SUCCESS';
    out_message := 'Account verified and activated.';
END;
$$;






CREATE OR REPLACE PROCEDURE validate_login(
    IN  p_email         VARCHAR(255),
    IN  p_password_hash VARCHAR(255),
    OUT out_status      VARCHAR(20),
    OUT out_message     TEXT,
    OUT out_user_id     UUID,
    OUT out_mfa_enabled BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user users%ROWTYPE;
BEGIN
    SELECT * INTO v_user
    FROM   users
    WHERE  email         = LOWER(TRIM(p_email))
      AND  auth_provider = 'email'
      AND  is_active     = TRUE;

    IF v_user IS NULL THEN
        out_status      := 'INVALID';
        out_message     := 'Incorrect email address or password.';
        out_user_id     := NULL;
        out_mfa_enabled := FALSE;
        RETURN;
    END IF;

    IF NOT v_user.is_email_verified THEN
        out_status      := 'UNVERIFIED';
        out_message     := 'Please verify your email address before logging in.';
        out_user_id     := NULL;
        out_mfa_enabled := FALSE;
        RETURN;
    END IF;

    IF v_user.locked_until IS NOT NULL
       AND v_user.locked_until > CURRENT_TIMESTAMP THEN
        out_status      := 'LOCKED';
        out_message     := 'Your account has been temporarily locked due to multiple failed login attempts. Please try again after 30 minutes or reset your password.';
        out_user_id     := NULL;
        out_mfa_enabled := FALSE;
        RETURN;
    END IF;

    IF v_user.password_hash <> p_password_hash THEN

        CALL record_failed_login(v_user.user_id);
        out_status      := 'INVALID';
        out_message     := 'Incorrect email address or password.';
        out_user_id     := NULL;
        out_mfa_enabled := FALSE;
        RETURN;
    END IF;

    
    CALL clear_failed_logins(v_user.user_id);
    out_status      := 'SUCCESS';
    out_message     := 'Login successful.';
    out_user_id     := v_user.user_id;
    out_mfa_enabled := v_user.mfa_enabled;
END;
$$;





CREATE OR REPLACE PROCEDURE record_failed_login(
    IN p_user_id UUID
)
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






CREATE OR REPLACE PROCEDURE clear_failed_logins(
    IN p_user_id UUID
)
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





CREATE OR REPLACE PROCEDURE create_session(
    IN  p_user_id           UUID,
    IN  p_session_token     VARCHAR(512),
    IN  p_device_info       TEXT,
    IN  p_ip_address        VARCHAR(45),
    OUT out_status          VARCHAR(20),
    OUT out_session_id      UUID,
    OUT out_expires_at      TIMESTAMP
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_expires TIMESTAMP;
BEGIN
    v_expires := CURRENT_TIMESTAMP + INTERVAL '24 hours';

    INSERT INTO user_sessions (
        user_id,
        session_token,
        device_info,
        ip_address,
        expires_at
    ) VALUES (
        p_user_id,
        p_session_token,
        p_device_info,
        p_ip_address,
        v_expires
    )
    RETURNING user_sessions.session_id INTO out_session_id;

    out_status     := 'SUCCESS';
    out_expires_at := v_expires;
END;
$$;






CREATE OR REPLACE PROCEDURE update_profile(
    IN  p_user_id      UUID,
    IN  p_first_name   VARCHAR(100),
    IN  p_last_name    VARCHAR(100),
    IN  p_phone_number VARCHAR(20),
    OUT out_status     VARCHAR(20),
    OUT out_message    TEXT
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
        out_status  := 'NOT_FOUND';
        out_message := 'Account not found.';
        RETURN;
    END IF;

    out_status  := 'SUCCESS';
    out_message := 'Profile updated successfully.';
END;
$$;





CREATE OR REPLACE PROCEDURE set_account_role(
    IN  p_user_id       UUID,
    IN  p_account_type  VARCHAR(20),
    OUT out_status      VARCHAR(20),
    OUT out_message     TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF p_account_type NOT IN ('customer', 'print_house', 'both') THEN
        out_status  := 'INVALID';
        out_message := 'Invalid account type specified.';
        RETURN;
    END IF;

    UPDATE users
    SET    account_type = p_account_type,
           updated_at   = CURRENT_TIMESTAMP
    WHERE  user_id   = p_user_id
      AND  is_active = TRUE;

    IF NOT FOUND THEN
        out_status  := 'NOT_FOUND';
        out_message := 'Account not found.';
        RETURN;
    END IF;

    out_status  := 'SUCCESS';
    out_message := 'Account role updated to: ' || p_account_type || '.';
END;
$$;






CREATE OR REPLACE PROCEDURE sp_set_mfa_status(
    IN  p_user_id   UUID,
    IN  p_enabled   BOOLEAN,
    OUT out_status  VARCHAR(20),
    OUT out_message TEXT
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
        out_status  := 'NOT_FOUND';
        out_message := 'Account not found.';
        RETURN;
    END IF;

    out_status := 'SUCCESS';

    IF p_enabled THEN
        out_message := 'Two-factor authentication has been enabled.';
    ELSE
        out_message := 'Two-factor authentication has been disabled.';
    END IF;
END;
$$;




CREATE OR REPLACE PROCEDURE get_google_user(
    IN  p_google_id               VARCHAR(255),
    OUT out_status                VARCHAR(20),
    OUT out_message               TEXT,
    OUT out_user_id               UUID,
    OUT out_email                 VARCHAR(255),
    OUT out_account_type          VARCHAR(20),
    OUT out_profile_completed     BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    SELECT
        u.user_id,
        u.email,
        u.account_type,
        u.profile_completed
    INTO
        out_user_id,
        out_email,
        out_account_type,
        out_profile_completed
    FROM users u
    WHERE u.google_id = p_google_id
      AND u.is_active = TRUE;

    IF out_user_id IS NULL THEN
        out_status            := 'NOT_FOUND';
        out_message           := 'No account linked to this Google ID.';
        out_email             := NULL;
        out_account_type      := NULL;
        out_profile_completed := NULL;
    ELSE
        out_status  := 'SUCCESS';
        out_message := 'Google user found.';
    END IF;
END;
$$;