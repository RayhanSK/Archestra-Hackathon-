-- ============================================================
-- ENTERPRISE INSIDER THREAT DETECTION DATABASE SCHEMA
-- Database: company_db
-- PostgreSQL 12+
-- ============================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- CORE REFERENCE TABLES
-- ============================================================

-- Employees table
CREATE TABLE employees (
    employee_id SERIAL PRIMARY KEY,
    employee_uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    employee_number VARCHAR(20) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    department VARCHAR(100) NOT NULL,
    title VARCHAR(150) NOT NULL,
    manager_id INTEGER REFERENCES employees(employee_id),
    employment_status VARCHAR(20) NOT NULL DEFAULT 'active',
    hire_date DATE NOT NULL,
    termination_date DATE,
    risk_score DECIMAL(5,2) DEFAULT 0.00,
    last_risk_assessment_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_employment_status CHECK (
        employment_status IN ('active', 'suspended', 'terminated', 'leave')
    ),
    CONSTRAINT valid_risk_score CHECK (risk_score >= 0 AND risk_score <= 100),
    CONSTRAINT valid_termination_logic CHECK (
        (employment_status = 'terminated' AND termination_date IS NOT NULL) OR
        (employment_status != 'terminated' AND termination_date IS NULL)
    )
);

CREATE INDEX idx_employees_status ON employees(employment_status);
CREATE INDEX idx_employees_department ON employees(department);
CREATE INDEX idx_employees_manager ON employees(manager_id);
CREATE INDEX idx_employees_email ON employees(email);

-- Roles table
CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(100) UNIQUE NOT NULL,
    role_level INTEGER NOT NULL,
    description TEXT,
    is_privileged BOOLEAN DEFAULT FALSE,
    requires_approval BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_role_level CHECK (role_level >= 0 AND role_level <= 100)
);

CREATE INDEX idx_roles_privileged ON roles(is_privileged);
CREATE INDEX idx_roles_level ON roles(role_level);

-- Employee roles (many-to-many with temporal tracking)
CREATE TABLE employee_roles (
    employee_role_id SERIAL PRIMARY KEY,
    employee_id INTEGER NOT NULL REFERENCES employees(employee_id),
    role_id INTEGER NOT NULL REFERENCES roles(role_id),
    assigned_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER REFERENCES employees(employee_id),
    revoked_date TIMESTAMP WITH TIME ZONE,
    revoked_by INTEGER REFERENCES employees(employee_id),
    revocation_reason TEXT,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_employee_roles_employee ON employee_roles(employee_id, is_active);
CREATE INDEX idx_employee_roles_role ON employee_roles(role_id);
CREATE INDEX idx_employee_roles_assigned_date ON employee_roles(assigned_date);

-- Employee schedules
CREATE TABLE employee_schedules (
    schedule_id SERIAL PRIMARY KEY,
    employee_id INTEGER NOT NULL REFERENCES employees(employee_id),
    day_of_week INTEGER NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    effective_from DATE NOT NULL,
    effective_to DATE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_day_of_week CHECK (day_of_week >= 0 AND day_of_week <= 6),
    CONSTRAINT valid_time_range CHECK (start_time < end_time)
);

CREATE INDEX idx_employee_schedules_employee ON employee_schedules(employee_id, is_active);
CREATE INDEX idx_employee_schedules_effective ON employee_schedules(effective_from, effective_to);

-- Systems table
CREATE TABLE systems (
    system_id SERIAL PRIMARY KEY,
    system_uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    system_name VARCHAR(200) UNIQUE NOT NULL,
    system_type VARCHAR(50) NOT NULL,
    sensitivity_level VARCHAR(20) NOT NULL,
    description TEXT,
    is_production BOOLEAN DEFAULT TRUE,
    requires_mfa BOOLEAN DEFAULT FALSE,
    owner_id INTEGER REFERENCES employees(employee_id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_sensitivity CHECK (
        sensitivity_level IN ('public', 'internal', 'confidential', 'restricted', 'top_secret')
    ),
    CONSTRAINT valid_system_type CHECK (
        system_type IN ('database', 'application', 'file_server', 'network_device', 
                       'cloud_service', 'erp', 'crm', 'scm', 'hr_system', 'financial_system')
    )
);

CREATE INDEX idx_systems_sensitivity ON systems(sensitivity_level);
CREATE INDEX idx_systems_type ON systems(system_type);
CREATE INDEX idx_systems_production ON systems(is_production);

-- System permissions
CREATE TABLE system_permissions (
    permission_id SERIAL PRIMARY KEY,
    system_id INTEGER NOT NULL REFERENCES systems(system_id),
    role_id INTEGER NOT NULL REFERENCES roles(role_id),
    permission_level VARCHAR(20) NOT NULL,
    granted_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    granted_by INTEGER REFERENCES employees(employee_id),
    revoked_date TIMESTAMP WITH TIME ZONE,
    revoked_by INTEGER REFERENCES employees(employee_id),
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT valid_permission_level CHECK (
        permission_level IN ('none', 'read', 'write', 'admin', 'owner')
    )
);

CREATE INDEX idx_system_permissions_system ON system_permissions(system_id, is_active);
CREATE INDEX idx_system_permissions_role ON system_permissions(role_id, is_active);

-- Devices table
CREATE TABLE devices (
    device_id SERIAL PRIMARY KEY,
    device_uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    device_fingerprint VARCHAR(64) UNIQUE NOT NULL,
    device_type VARCHAR(50) NOT NULL,
    device_name VARCHAR(200),
    os_type VARCHAR(50),
    os_version VARCHAR(50),
    browser VARCHAR(100),
    is_corporate_managed BOOLEAN DEFAULT FALSE,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_trusted BOOLEAN DEFAULT FALSE,
    is_blocked BOOLEAN DEFAULT FALSE,
    CONSTRAINT valid_device_type CHECK (
        device_type IN ('laptop', 'desktop', 'mobile', 'tablet', 'server', 'unknown')
    )
);

CREATE INDEX idx_devices_fingerprint ON devices(device_fingerprint);
CREATE INDEX idx_devices_corporate ON devices(is_corporate_managed);
CREATE INDEX idx_devices_trusted ON devices(is_trusted);

-- Employee devices
CREATE TABLE employee_devices (
    employee_device_id SERIAL PRIMARY KEY,
    employee_id INTEGER NOT NULL REFERENCES employees(employee_id),
    device_id INTEGER NOT NULL REFERENCES devices(device_id),
    first_used TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    usage_count INTEGER DEFAULT 1,
    is_primary BOOLEAN DEFAULT FALSE,
    UNIQUE (employee_id, device_id)
);

CREATE INDEX idx_employee_devices_employee ON employee_devices(employee_id);
CREATE INDEX idx_employee_devices_device ON employee_devices(device_id);
CREATE INDEX idx_employee_devices_primary ON employee_devices(employee_id, is_primary);

-- ============================================================
-- EVENT/ACTIVITY TABLES (IMMUTABLE LOGS)
-- ============================================================

-- Authentication events
CREATE TABLE authentication_events (
    auth_event_id BIGSERIAL PRIMARY KEY,
    event_uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    employee_id INTEGER NOT NULL REFERENCES employees(employee_id),
    device_id INTEGER REFERENCES devices(device_id),
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(30) NOT NULL,
    auth_method VARCHAR(50) NOT NULL,
    result VARCHAR(20) NOT NULL,
    failure_reason VARCHAR(200),
    ip_address INET NOT NULL,
    country_code CHAR(2),
    region VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10, 7),
    longitude DECIMAL(10, 7),
    user_agent TEXT,
    session_id VARCHAR(255),
    mfa_used BOOLEAN DEFAULT FALSE,
    CONSTRAINT valid_event_type CHECK (
        event_type IN ('login', 'logout', 'password_change', 'mfa_enrollment', 
                      'password_reset', 'session_refresh')
    ),
    CONSTRAINT valid_auth_method CHECK (
        auth_method IN ('password', 'sso', 'certificate', 'biometric', 'api_key', 'token')
    ),
    CONSTRAINT valid_result CHECK (
        result IN ('success', 'failure', 'blocked', 'requires_mfa')
    )
);

CREATE INDEX idx_auth_events_employee ON authentication_events(employee_id, event_timestamp DESC);
CREATE INDEX idx_auth_events_timestamp ON authentication_events(event_timestamp DESC);
CREATE INDEX idx_auth_events_result ON authentication_events(result, event_timestamp DESC);
CREATE INDEX idx_auth_events_ip ON authentication_events(ip_address);
CREATE INDEX idx_auth_events_device ON authentication_events(device_id);
CREATE INDEX idx_auth_events_location ON authentication_events(employee_id, latitude, longitude, event_timestamp);

-- Access logs
CREATE TABLE access_logs (
    access_log_id BIGSERIAL PRIMARY KEY,
    log_uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    employee_id INTEGER NOT NULL REFERENCES employees(employee_id),
    system_id INTEGER NOT NULL REFERENCES systems(system_id),
    device_id INTEGER REFERENCES devices(device_id),
    access_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    action_type VARCHAR(50) NOT NULL,
    resource_accessed TEXT,
    access_level VARCHAR(20) NOT NULL,
    result VARCHAR(20) NOT NULL,
    ip_address INET NOT NULL,
    country_code CHAR(2),
    region VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10, 7),
    longitude DECIMAL(10, 7),
    session_id VARCHAR(255),
    duration_seconds INTEGER,
    CONSTRAINT valid_action_type CHECK (
        action_type IN ('view', 'create', 'update', 'delete', 'export', 'download', 
                       'upload', 'execute', 'configure', 'admin_action')
    ),
    CONSTRAINT valid_access_level CHECK (
        access_level IN ('read', 'write', 'admin', 'owner')
    ),
    CONSTRAINT valid_access_result CHECK (
        result IN ('success', 'denied', 'blocked', 'error')
    )
);

CREATE INDEX idx_access_logs_employee ON access_logs(employee_id, access_timestamp DESC);
CREATE INDEX idx_access_logs_system ON access_logs(system_id, access_timestamp DESC);
CREATE INDEX idx_access_logs_timestamp ON access_logs(access_timestamp DESC);
CREATE INDEX idx_access_logs_action ON access_logs(action_type, result);
CREATE INDEX idx_access_logs_denied ON access_logs(result, access_timestamp DESC) WHERE result = 'denied';
CREATE INDEX idx_access_logs_location ON access_logs(employee_id, latitude, longitude, access_timestamp);

-- Data activity logs
CREATE TABLE data_activity_logs (
    activity_log_id BIGSERIAL PRIMARY KEY,
    log_uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    employee_id INTEGER NOT NULL REFERENCES employees(employee_id),
    system_id INTEGER NOT NULL REFERENCES systems(system_id),
    activity_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    activity_type VARCHAR(50) NOT NULL,
    object_type VARCHAR(50) NOT NULL,
    object_name TEXT,
    object_path TEXT,
    record_count INTEGER DEFAULT 0,
    data_volume_bytes BIGINT DEFAULT 0,
    operation_result VARCHAR(20) NOT NULL,
    ip_address INET NOT NULL,
    session_id VARCHAR(255),
    CONSTRAINT valid_activity_type CHECK (
        activity_type IN ('query', 'export', 'download', 'upload', 'copy', 'move', 
                         'delete', 'bulk_update', 'backup', 'restore')
    ),
    CONSTRAINT valid_object_type CHECK (
        object_type IN ('file', 'database_table', 'report', 'document', 'record_set', 
                       'backup_file', 'configuration', 'log_file')
    ),
    CONSTRAINT valid_operation_result CHECK (
        operation_result IN ('success', 'partial', 'failed', 'blocked')
    )
);

CREATE INDEX idx_data_activity_employee ON data_activity_logs(employee_id, activity_timestamp DESC);
CREATE INDEX idx_data_activity_system ON data_activity_logs(system_id, activity_timestamp DESC);
CREATE INDEX idx_data_activity_timestamp ON data_activity_logs(activity_timestamp DESC);
CREATE INDEX idx_data_activity_volume ON data_activity_logs(employee_id, data_volume_bytes DESC);
CREATE INDEX idx_data_activity_type ON data_activity_logs(activity_type, operation_result);

-- Permission changes
CREATE TABLE permission_changes (
    change_id BIGSERIAL PRIMARY KEY,
    change_uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    change_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    change_type VARCHAR(50) NOT NULL,
    target_employee_id INTEGER NOT NULL REFERENCES employees(employee_id),
    changed_by INTEGER NOT NULL REFERENCES employees(employee_id),
    role_id INTEGER REFERENCES roles(role_id),
    system_id INTEGER REFERENCES systems(system_id),
    old_permission_level VARCHAR(20),
    new_permission_level VARCHAR(20),
    justification TEXT,
    approval_required BOOLEAN DEFAULT FALSE,
    approved_by INTEGER REFERENCES employees(employee_id),
    approval_timestamp TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    CONSTRAINT valid_change_type CHECK (
        change_type IN ('role_assignment', 'role_revocation', 'permission_grant', 
                       'permission_revoke', 'privilege_escalation', 'access_modification')
    ),
    CONSTRAINT approval_logic CHECK (
        (approval_required = FALSE) OR 
        (approval_required = TRUE AND approved_by IS NOT NULL)
    )
);

CREATE INDEX idx_permission_changes_target ON permission_changes(target_employee_id, change_timestamp DESC);
CREATE INDEX idx_permission_changes_changer ON permission_changes(changed_by, change_timestamp DESC);
CREATE INDEX idx_permission_changes_timestamp ON permission_changes(change_timestamp DESC);
CREATE INDEX idx_permission_changes_type ON permission_changes(change_type);
CREATE INDEX idx_permission_changes_escalation ON permission_changes(change_type, change_timestamp DESC) 
    WHERE change_type = 'privilege_escalation';

-- ============================================================
-- ALERT AND DETECTION TABLES
-- ============================================================

-- Alert types
CREATE TABLE alert_types (
    alert_type_id SERIAL PRIMARY KEY,
    alert_code VARCHAR(50) UNIQUE NOT NULL,
    alert_name VARCHAR(200) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    auto_escalate BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_severity CHECK (
        severity IN ('info', 'low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT valid_category CHECK (
        category IN ('impossible_travel', 'privilege_escalation', 'audit_tampering', 
                    'brute_force', 'data_exfiltration', 'after_hours', 'anomalous_behavior')
    )
);

CREATE INDEX idx_alert_types_category ON alert_types(category);
CREATE INDEX idx_alert_types_severity ON alert_types(severity);

-- Alerts
CREATE TABLE alerts (
    alert_id BIGSERIAL PRIMARY KEY,
    alert_uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    alert_type_id INTEGER NOT NULL REFERENCES alert_types(alert_type_id),
    employee_id INTEGER NOT NULL REFERENCES employees(employee_id),
    generated_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    confidence_score DECIMAL(5,2) NOT NULL,
    description TEXT NOT NULL,
    evidence_summary JSONB,
    related_event_ids JSONB,
    assigned_to INTEGER REFERENCES employees(employee_id),
    assigned_timestamp TIMESTAMP WITH TIME ZONE,
    resolved_timestamp TIMESTAMP WITH TIME ZONE,
    resolved_by INTEGER REFERENCES employees(employee_id),
    resolution_notes TEXT,
    false_positive BOOLEAN,
    escalated BOOLEAN DEFAULT FALSE,
    escalated_to INTEGER REFERENCES employees(employee_id),
    escalated_timestamp TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_alert_severity CHECK (
        severity IN ('info', 'low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT valid_alert_status CHECK (
        status IN ('open', 'investigating', 'resolved', 'closed', 'escalated', 'false_positive')
    ),
    CONSTRAINT valid_confidence_score CHECK (
        confidence_score >= 0 AND confidence_score <= 100
    )
);

CREATE INDEX idx_alerts_employee ON alerts(employee_id, generated_timestamp DESC);
CREATE INDEX idx_alerts_type ON alerts(alert_type_id, status);
CREATE INDEX idx_alerts_timestamp ON alerts(generated_timestamp DESC);
CREATE INDEX idx_alerts_status ON alerts(status, severity);
CREATE INDEX idx_alerts_severity ON alerts(severity, generated_timestamp DESC);
CREATE INDEX idx_alerts_assigned ON alerts(assigned_to, status);

-- Audit log tampering
CREATE TABLE audit_log_tampering (
    tampering_id BIGSERIAL PRIMARY KEY,
    tampering_uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    detected_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    employee_id INTEGER NOT NULL REFERENCES employees(employee_id),
    action_attempted VARCHAR(50) NOT NULL,
    target_table VARCHAR(100) NOT NULL,
    target_record_id BIGINT,
    sql_command TEXT,
    ip_address INET NOT NULL,
    device_id INTEGER REFERENCES devices(device_id),
    blocked BOOLEAN DEFAULT TRUE,
    alert_generated BOOLEAN DEFAULT TRUE,
    CONSTRAINT valid_tampering_action CHECK (
        action_attempted IN ('delete', 'update', 'truncate', 'drop', 'alter', 'disable_trigger')
    )
);

CREATE INDEX idx_audit_tampering_employee ON audit_log_tampering(employee_id, detected_timestamp DESC);
CREATE INDEX idx_audit_tampering_timestamp ON audit_log_tampering(detected_timestamp DESC);
CREATE INDEX idx_audit_tampering_target ON audit_log_tampering(target_table);

-- ============================================================
-- AUDIT PROTECTION TRIGGERS
-- ============================================================

-- Function to prevent tampering with immutable tables
CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    -- Log the tampering attempt
    INSERT INTO audit_log_tampering (
        employee_id,
        action_attempted,
        target_table,
        target_record_id,
        sql_command,
        ip_address,
        blocked,
        alert_generated
    ) VALUES (
        COALESCE(NULLIF(current_setting('app.current_employee_id', true), '')::INTEGER, 0),
        TG_OP,
        TG_TABLE_NAME,
        CASE 
            WHEN TG_OP = 'DELETE' THEN OLD.access_log_id 
            WHEN TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'access_logs' THEN NEW.access_log_id
            WHEN TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'authentication_events' THEN NEW.auth_event_id
            WHEN TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'data_activity_logs' THEN NEW.activity_log_id
            ELSE NULL
        END,
        current_query(),
        inet_client_addr(),
        TRUE,
        TRUE
    );
    
    -- Prevent the operation
    RAISE EXCEPTION 'Audit log tampering detected and prevented. Incident logged.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers to immutable tables
CREATE TRIGGER prevent_access_log_tampering
    BEFORE DELETE OR UPDATE ON access_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_tampering();

CREATE TRIGGER prevent_auth_events_tampering
    BEFORE DELETE OR UPDATE ON authentication_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_tampering();

CREATE TRIGGER prevent_data_activity_tampering
    BEFORE DELETE OR UPDATE ON data_activity_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_tampering();

-- ============================================================
-- UTILITY VIEWS FOR COMMON QUERIES
-- ============================================================

-- Active employees with their roles
CREATE VIEW v_active_employee_roles AS
SELECT 
    e.employee_id,
    e.employee_number,
    e.email,
    e.first_name,
    e.last_name,
    e.department,
    e.title,
    r.role_id,
    r.role_name,
    r.role_level,
    r.is_privileged,
    er.assigned_date,
    er.assigned_by
FROM employees e
JOIN employee_roles er ON e.employee_id = er.employee_id
JOIN roles r ON er.role_id = r.role_id
WHERE e.employment_status = 'active'
    AND er.is_active = TRUE;

-- Recent high-severity alerts
CREATE VIEW v_critical_alerts AS
SELECT 
    a.alert_id,
    a.generated_timestamp,
    at.alert_name,
    at.category,
    a.severity,
    a.status,
    e.employee_number,
    e.email,
    e.first_name || ' ' || e.last_name AS employee_name,
    a.description,
    a.confidence_score
FROM alerts a
JOIN alert_types at ON a.alert_type_id = at.alert_type_id
JOIN employees e ON a.employee_id = e.employee_id
WHERE a.severity IN ('high', 'critical')
    AND a.status IN ('open', 'investigating')
ORDER BY a.generated_timestamp DESC;

COMMENT ON TABLE employees IS 'Master employee registry with employment status tracking';
COMMENT ON TABLE authentication_events IS 'Immutable log of all authentication attempts - DO NOT UPDATE OR DELETE';
COMMENT ON TABLE access_logs IS 'Immutable log of all system access events - DO NOT UPDATE OR DELETE';
COMMENT ON TABLE data_activity_logs IS 'Immutable log of data operations with volume tracking - DO NOT UPDATE OR DELETE';