-- =====================================================
-- SNOWFLAKE USER AND ROLE DATA EXTRACTION SETUP
-- =====================================================
-- This script sets up staging tables, procedures, and scheduled tasks
-- to extract user and role data from Snowflake with minimal privileges

-- =====================================================
-- PART 1: DATABASE AND SCHEMA SETUP
-- =====================================================

-- Create database and schema (run as SYSADMIN or higher)
CREATE DATABASE IF NOT EXISTS TRELICA;
USE DATABASE TRELICA;
CREATE SCHEMA IF NOT EXISTS USER_ROLE_STAGING;
USE SCHEMA USER_ROLE_STAGING;

-- =====================================================
-- PART 2: CREATE STAGING TABLES
-- =====================================================

-- 1. Roles staging table with metadata
CREATE OR REPLACE TABLE TRELICA.USER_ROLE_STAGING.ROLES_STAGING (
    role_name VARCHAR(255) NOT NULL,
    role_owner VARCHAR(255),
    created_on TIMESTAMP_NTZ,
    comment VARCHAR(16777216),
    assigned_user_count NUMBER(38,0),
    granted_role_count NUMBER(38,0),
    granted_to_role_count NUMBER(38,0),
    last_updated TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (role_name)
);

-- 2. User-to-role assignments staging table
CREATE OR REPLACE TABLE TRELICA.USER_ROLE_STAGING.USER_ROLE_ASSIGNMENTS_STAGING (
    user_name VARCHAR(255) NOT NULL,
    role_name VARCHAR(255) NOT NULL,
    granted_on TIMESTAMP_NTZ,
    granted_by VARCHAR(255),
    default_role BOOLEAN DEFAULT FALSE,
    last_updated TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (user_name, role_name)
);


-- 4. User information staging table
CREATE OR REPLACE TABLE TRELICA.USER_ROLE_STAGING.USERS_STAGING (
    user_name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    created_on TIMESTAMP_NTZ,
    disabled BOOLEAN,
    locked BOOLEAN,
    default_warehouse VARCHAR(255),
    default_namespace VARCHAR(255),
    default_role VARCHAR(255),
    ext_authn_duo BOOLEAN,
    ext_authn_uid VARCHAR(255),
    must_change_password BOOLEAN,
    snowflake_lock BOOLEAN,
    last_updated TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (user_name)
);

-- 5. MFA enrollment status staging table
CREATE OR REPLACE TABLE TRELICA.USER_ROLE_STAGING.USER_MFA_ENROLLMENT_STAGING (
    user_name VARCHAR(255) NOT NULL,
    mfa_enrolled BOOLEAN DEFAULT FALSE,
    enrollment_status VARCHAR(50),
    last_updated TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (user_name)
);

-- 6. Session summary staging table (optimized for performance)
CREATE OR REPLACE TABLE TRELICA.USER_ROLE_STAGING.USER_SESSION_SUMMARY_STAGING (
    user_name VARCHAR(255) NOT NULL,
    last_successful_login TIMESTAMP_NTZ,
    days_since_last_login NUMBER(38,0),
    failed_login_attempts_last_year NUMBER(38,0),
    most_recent_client_ip VARCHAR(255),
    last_updated TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (user_name)
);

-- =====================================================
-- PART 3: CREATE STORED PROCEDURE FOR DATA EXTRACTION
-- =====================================================

CREATE OR REPLACE PROCEDURE TRELICA.USER_ROLE_STAGING.EXTRACT_USER_ROLE_DATA()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
BEGIN
   -- 1. Extract roles with metadata (using INFORMATION_SCHEMA for performance)
    TRUNCATE TABLE TRELICA.USER_ROLE_STAGING.ROLES_STAGING;
    
    -- Note: INFORMATION_SCHEMA doesn't have all metadata like owner and created_on
    -- We'll get basic role info from INFORMATION_SCHEMA and counts only
    INSERT INTO TRELICA.USER_ROLE_STAGING.ROLES_STAGING (
          role_name,
          role_owner,
          created_on,
          comment,
          assigned_user_count,
          granted_role_count,       -- # of roles granted TO this role (parents it inherits)
          granted_to_role_count,    -- # of roles this role is granted TO (children that inherit it)
          last_updated
        )
        WITH roles AS (
          SELECT
            NAME        AS role_name,
            OWNER       AS role_owner,
            CREATED_ON  AS created_on,
            COMMENT     AS comment
          FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
          WHERE DELETED_ON IS NULL
            AND ROLE_TYPE = 'ROLE'          -- keep only account-level roles; drop this line to include db/app roles
        ),
        user_counts AS (
          SELECT
            ROLE AS role_name,
            COUNT(DISTINCT GRANTEE_NAME) AS assigned_user_count
          FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
          WHERE DELETED_ON IS NULL
          GROUP BY ROLE
        ),
        role_parents AS (                       -- roles granted TO this role
          SELECT
            GRANTEE_NAME AS role_name,
            COUNT(DISTINCT NAME) AS parent_role_count
          FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
          WHERE DELETED_ON IS NULL
            AND GRANTED_TO IN ('ROLE')         -- include DATABASE_ROLE too if you want those relationships
            AND GRANTED_ON = 'ROLE'
          GROUP BY GRANTEE_NAME
        ),
        role_children AS (                      -- roles this role is granted TO
          SELECT
            NAME AS role_name,
            COUNT(DISTINCT GRANTEE_NAME) AS child_role_count
          FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
          WHERE DELETED_ON IS NULL
            AND GRANTED_TO IN ('ROLE')
            AND GRANTED_ON = 'ROLE'
          GROUP BY NAME
        )
        SELECT
          r.role_name,
          r.role_owner,
          r.created_on,
          r.comment,
          COALESCE(u.assigned_user_count, 0)                 AS assigned_user_count,
          COALESCE(p.parent_role_count, 0)                   AS granted_role_count,
          COALESCE(c.child_role_count, 0)                    AS granted_to_role_count,
          CURRENT_TIMESTAMP()                                AS last_updated
        FROM roles r
        LEFT JOIN user_counts  u USING (role_name)
        LEFT JOIN role_parents p USING (role_name)
        LEFT JOIN role_children c USING (role_name);
    
    -- 2. Extract user-to-role assignments (using INFORMATION_SCHEMA)
    TRUNCATE TABLE TRELICA.USER_ROLE_STAGING.USER_ROLE_ASSIGNMENTS_STAGING;
    
    INSERT INTO TRELICA.USER_ROLE_STAGING.USER_ROLE_ASSIGNMENTS_STAGING (
        user_name,
        role_name,
        default_role,
        last_updated
    )
    SELECT 
        ar.grantee AS user_name,
        ar.role_name,
        FALSE AS default_role,  -- Will need to update from USERS table
        CURRENT_TIMESTAMP() AS last_updated
    FROM INFORMATION_SCHEMA.APPLICABLE_ROLES ar;
    
    -- Update default role flag
    UPDATE TRELICA.USER_ROLE_STAGING.USER_ROLE_ASSIGNMENTS_STAGING ura
    SET default_role = TRUE
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
    WHERE ura.user_name = u.name 
      AND ura.role_name = u.default_role
      AND u.deleted_on IS NULL;
    
    -- 4. Extract user information
    TRUNCATE TABLE TRELICA.USER_ROLE_STAGING.USERS_STAGING;
    
    INSERT INTO TRELICA.USER_ROLE_STAGING.USERS_STAGING (
        user_name,
        display_name,
        first_name,
        last_name,
        email,
        created_on,
        disabled,
        locked,
        default_warehouse,
        default_namespace,
        default_role,
        ext_authn_duo,
        ext_authn_uid,
        must_change_password,
        snowflake_lock,
        last_updated
    )
    SELECT 
        name AS user_name,
        display_name,
        first_name,
        last_name,
        email,
        created_on,
        disabled,
        CASE WHEN locked_until_time > CURRENT_TIMESTAMP() THEN TRUE ELSE FALSE END AS locked,
        default_warehouse,
        default_namespace,
        default_role,
        ext_authn_duo,
        ext_authn_uid,
        must_change_password,
        snowflake_lock,
        CURRENT_TIMESTAMP() AS last_updated
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
    WHERE deleted_on IS NULL;
    
    -- 5. Extract MFA enrollment status
    TRUNCATE TABLE TRELICA.USER_ROLE_STAGING.USER_MFA_ENROLLMENT_STAGING;
    
    INSERT INTO TRELICA.USER_ROLE_STAGING.USER_MFA_ENROLLMENT_STAGING (
        user_name,
        mfa_enrolled,
        enrollment_status,
        last_updated
    )
    SELECT 
        u.name AS user_name,
        CASE 
            WHEN u.ext_authn_duo = TRUE THEN TRUE
            WHEN lh.second_authentication_factor IS NOT NULL THEN TRUE
            ELSE FALSE
        END AS mfa_enrolled,
        CASE 
            WHEN u.ext_authn_duo = TRUE THEN 'DUO'
            WHEN lh.second_authentication_factor IS NOT NULL THEN 'SNOWFLAKE_MFA'
            ELSE 'NOT_ENROLLED'
        END AS enrollment_status,
        CURRENT_TIMESTAMP() AS last_updated
    FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
    LEFT JOIN (
        SELECT DISTINCT 
            user_name,
            FIRST_VALUE(second_authentication_factor) OVER (
                PARTITION BY user_name 
                ORDER BY event_timestamp DESC
            ) AS second_authentication_factor
        FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
        WHERE event_timestamp >= DATEADD(YEAR, -1, CURRENT_TIMESTAMP())
            AND second_authentication_factor IS NOT NULL
    ) lh ON u.name = lh.user_name
    WHERE u.deleted_on IS NULL;
    
    -- 6. Extract session summary (optimized for performance)
    TRUNCATE TABLE TRELICA.USER_ROLE_STAGING.USER_SESSION_SUMMARY_STAGING;
    
    -- Create temporary table for login summary
    CREATE OR REPLACE TEMPORARY TABLE login_summary AS
    SELECT 
        user_name,
        MAX(CASE WHEN is_success = 'YES' THEN event_timestamp END) AS last_successful_login,
        COUNT(CASE WHEN is_success = 'NO' THEN 1 END) AS failed_attempts,
        MAX(CASE WHEN is_success = 'YES' THEN client_ip END) AS last_success_ip,
        MAX(event_timestamp) AS last_activity
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE event_timestamp >= DATEADD(YEAR, -1, CURRENT_TIMESTAMP())
    GROUP BY user_name;
    
    INSERT INTO TRELICA.USER_ROLE_STAGING.USER_SESSION_SUMMARY_STAGING (
        user_name,
        last_successful_login,
        days_since_last_login,
        failed_login_attempts_last_year,
        most_recent_client_ip,
        last_updated
    )
    SELECT 
        ls.user_name,
        ls.last_successful_login,
        DATEDIFF(DAY, ls.last_successful_login, CURRENT_TIMESTAMP()) AS days_since_last_login,
        ls.failed_attempts AS failed_login_attempts_last_year,
        ls.last_success_ip AS most_recent_client_ip,
        CURRENT_TIMESTAMP() AS last_updated
    FROM login_summary ls
    WHERE ls.last_successful_login IS NOT NULL 
       OR ls.failed_attempts > 0;
    
    -- Drop temporary table
    DROP TABLE IF EXISTS login_summary;
    
    RETURN 'User and role data extraction completed successfully at ' || CURRENT_TIMESTAMP()::VARCHAR;
    
EXCEPTION
    WHEN OTHER THEN
        RETURN 'Error during extraction: ' || SQLERRM;
END;
$$;

-- =====================================================
-- PART 4: CREATE SCHEDULED TASK
-- =====================================================

-- Create a task that runs daily at 2 AM UTC
CREATE OR REPLACE TASK TRELICA.USER_ROLE_STAGING.DAILY_USER_ROLE_EXTRACTION_TASK
    WAREHOUSE = YOUR_WAREHOUSE  -- Replace with your warehouse name
    SCHEDULE = 'USING CRON 0 2 * * * UTC'  -- Daily at 2 AM UTC
    COMMENT = 'Daily extraction of user and role data to staging tables'
AS
    CALL TRELICA.USER_ROLE_STAGING.EXTRACT_USER_ROLE_DATA();

-- Enable the task (requires EXECUTE TASK privilege)
ALTER TASK TRELICA.USER_ROLE_STAGING.DAILY_USER_ROLE_EXTRACTION_TASK RESUME;

-- =====================================================
-- PART 5: CREATE LOW-PRIVILEGE READER ROLE
-- =====================================================

-- Create the reader role
CREATE ROLE IF NOT EXISTS TRELICA_READER
    COMMENT = 'Read-only access to TRELICA staging tables';

-- Grant usage on database and schema
GRANT USAGE ON DATABASE TRELICA TO ROLE TRELICA_READER;
GRANT USAGE ON SCHEMA TRELICA.USER_ROLE_STAGING TO ROLE TRELICA_READER;

-- Grant SELECT on all staging tables
GRANT SELECT ON TABLE TRELICA.USER_ROLE_STAGING.ROLES_STAGING TO ROLE TRELICA_READER;
GRANT SELECT ON TABLE TRELICA.USER_ROLE_STAGING.USER_ROLE_ASSIGNMENTS_STAGING TO ROLE TRELICA_READER;
GRANT SELECT ON TABLE TRELICA.USER_ROLE_STAGING.USERS_STAGING TO ROLE TRELICA_READER;
GRANT SELECT ON TABLE TRELICA.USER_ROLE_STAGING.USER_MFA_ENROLLMENT_STAGING TO ROLE TRELICA_READER;
GRANT SELECT ON TABLE TRELICA.USER_ROLE_STAGING.USER_SESSION_SUMMARY_STAGING TO ROLE TRELICA_READER;

-- Grant future SELECT privileges on any new tables in the schema
GRANT SELECT ON FUTURE TABLES IN SCHEMA TRELICA.USER_ROLE_STAGING TO ROLE TRELICA_READER;
