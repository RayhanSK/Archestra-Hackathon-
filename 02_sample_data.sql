-- ============================================================
-- SAMPLE DATA FOR ENTERPRISE SECURITY DATABASE
-- Realistic test data for insider threat detection
-- ============================================================

-- ============================================================
-- REFERENCE DATA
-- ============================================================

-- Insert Roles
INSERT INTO roles (role_name, role_level, description, is_privileged, requires_approval) VALUES
('User', 10, 'Standard employee access', FALSE, FALSE),
('Team Lead', 20, 'Team leadership with limited admin access', FALSE, FALSE),
('Senior Developer', 30, 'Senior technical role with elevated access', FALSE, FALSE),
('Database Administrator', 50, 'Full database access and management', TRUE, TRUE),
('System Administrator', 60, 'Full system access and configuration', TRUE, TRUE),
('Security Analyst', 55, 'Security monitoring and investigation', TRUE, TRUE),
('Finance Manager', 40, 'Financial system access', FALSE, TRUE),
('HR Manager', 40, 'HR system access', FALSE, TRUE),
('IT Director', 70, 'IT department leadership', TRUE, TRUE),
('CISO', 80, 'Chief Information Security Officer', TRUE, TRUE),
('CEO', 90, 'Chief Executive Officer', TRUE, TRUE);

-- Insert Systems
INSERT INTO systems (system_name, system_type, sensitivity_level, description, is_production, requires_mfa) VALUES
('Employee Database', 'database', 'confidential', 'HR employee records and PII', TRUE, TRUE),
('Financial ERP', 'erp', 'restricted', 'SAP financial system', TRUE, TRUE),
('Customer CRM', 'crm', 'confidential', 'Salesforce customer data', TRUE, TRUE),
('Source Code Repository', 'application', 'internal', 'GitHub Enterprise', TRUE, FALSE),
('Production Database Cluster', 'database', 'top_secret', 'PostgreSQL production cluster', TRUE, TRUE),
('Development Environment', 'application', 'internal', 'Development servers', FALSE, FALSE),
('File Server', 'file_server', 'confidential', 'Corporate file storage', TRUE, FALSE),
('VPN Gateway', 'network_device', 'restricted', 'Corporate VPN access', TRUE, TRUE),
('Email Server', 'application', 'confidential', 'Exchange server', TRUE, FALSE),
('Backup System', 'application', 'restricted', 'Veeam backup infrastructure', TRUE, TRUE);

-- Insert Employees (including some terminated/suspicious ones)
INSERT INTO employees (employee_number, email, first_name, last_name, department, title, employment_status, hire_date, manager_id, risk_score,termination_date) VALUES
-- IT Department
('EMP001', 'john.doe@company.com', 'John', 'Doe', 'IT', 'CISO', 'active', '2018-03-15', NULL, 5.00, NULL),
('EMP002', 'jane.smith@company.com', 'Jane', 'Smith', 'IT', 'IT Director', 'active', '2019-06-01', 1, 8.50, NULL),
('EMP003', 'bob.wilson@company.com', 'Bob', 'Wilson', 'IT', 'Database Administrator', 'active', '2020-01-10', 2, 12.30, NULL),
('EMP004', 'alice.johnson@company.com', 'Alice', 'Johnson', 'IT', 'System Administrator', 'active', '2020-05-20', 2, 7.20, NULL),
('EMP005', 'charlie.brown@company.com', 'Charlie', 'Brown', 'IT', 'Security Analyst', 'active', '2021-02-14', 1, 6.80, NULL),

-- Development Team
('EMP006', 'david.miller@company.com', 'David', 'Miller', 'Engineering', 'Senior Developer', 'active', '2019-09-01', 2, 15.40,NULL),
('EMP007', 'emma.davis@company.com', 'Emma', 'Davis', 'Engineering', 'Team Lead', 'active', '2020-11-15', 2, 9.10, NULL),
('EMP008', 'frank.garcia@company.com', 'Frank', 'Garcia', 'Engineering', 'Developer', 'active', '2021-07-01', 7, 5.50, NULL),

-- Finance Department
('EMP009', 'grace.martinez@company.com', 'Grace', 'Martinez', 'Finance', 'Finance Manager', 'active', '2018-08-20', NULL, 11.20, NULL),
('EMP010', 'henry.rodriguez@company.com', 'Henry', 'Rodriguez', 'Finance', 'Senior Accountant', 'active', '2019-12-05', 9, 8.90, NULL),

-- HR Department
('EMP011', 'isabel.lopez@company.com', 'Isabel', 'Lopez', 'HR', 'HR Manager', 'active', '2019-04-10', NULL, 6.50, NULL),
('EMP012', 'jack.gonzalez@company.com', 'Jack', 'Gonzalez', 'HR', 'HR Specialist', 'active', '2021-01-20', 11, 4.30, NULL),

-- Sales Department
('EMP013', 'karen.anderson@company.com', 'Karen', 'Anderson', 'Sales', 'Sales Director', 'active', '2018-05-15', NULL, 7.80, NULL),
('EMP014', 'leo.thomas@company.com', 'Leo', 'Thomas', 'Sales', 'Account Executive', 'active', '2020-08-01', 13, 18.50, NULL),

-- Recently Terminated (Suspicious)
('EMP015', 'mike.taylor@company.com', 'Mike', 'Taylor', 'IT', 'System Administrator', 'terminated', '2019-03-10', 2, 45.70, '2024-01-01'),

-- On Leave
('EMP016', 'nancy.moore@company.com', 'Nancy', 'Moore', 'Finance', 'Financial Analyst', 'leave', '2020-06-15', 9, 5.20, NULL);

-- Update manager relationships
UPDATE employees SET manager_id = 1 WHERE employee_number = 'EMP002';
UPDATE employees SET manager_id = 2 WHERE employee_number IN ('EMP003', 'EMP004', 'EMP006', 'EMP007');

-- Insert Employee Roles
INSERT INTO employee_roles (employee_id, role_id, assigned_by, is_active) VALUES
-- CISO
(1, 10, 1, TRUE),  -- CISO role
-- IT Director
(2, 9, 1, TRUE),   -- IT Director role
-- Database Admin
(3, 4, 2, TRUE),   -- Database Administrator role
-- System Admin
(4, 5, 2, TRUE),   -- System Administrator role
-- Security Analyst
(5, 6, 1, TRUE),   -- Security Analyst role
-- Senior Developer
(6, 3, 2, TRUE),   -- Senior Developer role
-- Team Lead
(7, 2, 2, TRUE),   -- Team Lead role
-- Developer
(8, 1, 7, TRUE),   -- User role
-- Finance Manager
(9, 7, 1, TRUE),   -- Finance Manager role
-- Senior Accountant
(10, 1, 9, TRUE),  -- User role
-- HR Manager
(11, 8, 1, TRUE),  -- HR Manager role
-- HR Specialist
(12, 1, 11, TRUE), -- User role
-- Sales Director
(13, 2, 1, TRUE),  -- Team Lead role
-- Account Executive
(14, 1, 13, TRUE), -- User role
-- Terminated employee (had System Admin)
(15, 5, 2, FALSE); -- System Administrator role (revoked)

-- Insert System Permissions (role-based access)
INSERT INTO system_permissions (system_id, role_id, permission_level, granted_by, is_active) VALUES
-- Employee Database access
(1, 8, 'admin', 1, TRUE),    -- HR Manager: admin
(1, 1, 'read', 1, TRUE),     -- User: read
(1, 4, 'admin', 1, TRUE),    -- DBA: admin

-- Financial ERP
(2, 7, 'admin', 1, TRUE),    -- Finance Manager: admin
(2, 1, 'read', 1, TRUE),     -- User: read

-- Customer CRM
(3, 2, 'write', 1, TRUE),    -- Team Lead: write
(3, 1, 'read', 1, TRUE),     -- User: read

-- Source Code Repository
(4, 3, 'write', 1, TRUE),    -- Senior Developer: write
(4, 2, 'write', 1, TRUE),    -- Team Lead: write
(4, 1, 'read', 1, TRUE),     -- User: read

-- Production Database
(5, 4, 'admin', 1, TRUE),    -- DBA: admin
(5, 9, 'admin', 1, TRUE),    -- IT Director: admin
(5, 10, 'owner', 1, TRUE),   -- CISO: owner

-- Development Environment
(6, 3, 'admin', 1, TRUE),    -- Senior Developer: admin
(6, 1, 'write', 1, TRUE),    -- User: write

-- File Server
(7, 1, 'write', 1, TRUE),    -- User: write
(7, 5, 'admin', 1, TRUE),    -- System Admin: admin

-- VPN Gateway
(8, 5, 'admin', 1, TRUE),    -- System Admin: admin
(8, 9, 'admin', 1, TRUE),    -- IT Director: admin

-- Email Server
(9, 5, 'admin', 1, TRUE),    -- System Admin: admin
(9, 1, 'read', 1, TRUE),     -- User: read

-- Backup System
(10, 5, 'admin', 1, TRUE),   -- System Admin: admin
(10, 4, 'admin', 1, TRUE);   -- DBA: admin

-- Insert Employee Schedules (Monday-Friday, 9 AM - 5 PM in various timezones)
INSERT INTO employee_schedules (employee_id, day_of_week, start_time, end_time, timezone, effective_from, is_active) VALUES
-- John Doe (CISO) - San Francisco timezone
(1, 1, '09:00', '17:00', 'America/Los_Angeles', '2023-01-01', TRUE),
(1, 2, '09:00', '17:00', 'America/Los_Angeles', '2023-01-01', TRUE),
(1, 3, '09:00', '17:00', 'America/Los_Angeles', '2023-01-01', TRUE),
(1, 4, '09:00', '17:00', 'America/Los_Angeles', '2023-01-01', TRUE),
(1, 5, '09:00', '17:00', 'America/Los_Angeles', '2023-01-01', TRUE),

-- Jane Smith (IT Director) - New York timezone
(2, 1, '08:30', '17:30', 'America/New_York', '2023-01-01', TRUE),
(2, 2, '08:30', '17:30', 'America/New_York', '2023-01-01', TRUE),
(2, 3, '08:30', '17:30', 'America/New_York', '2023-01-01', TRUE),
(2, 4, '08:30', '17:30', 'America/New_York', '2023-01-01', TRUE),
(2, 5, '08:30', '17:30', 'America/New_York', '2023-01-01', TRUE),

-- Bob Wilson (DBA) - New York timezone
(3, 1, '09:00', '18:00', 'America/New_York', '2023-01-01', TRUE),
(3, 2, '09:00', '18:00', 'America/New_York', '2023-01-01', TRUE),
(3, 3, '09:00', '18:00', 'America/New_York', '2023-01-01', TRUE),
(3, 4, '09:00', '18:00', 'America/New_York', '2023-01-01', TRUE),
(3, 5, '09:00', '18:00', 'America/New_York', '2023-01-01', TRUE),

-- David Miller (Senior Developer) - London timezone
(6, 1, '09:00', '17:30', 'Europe/London', '2023-01-01', TRUE),
(6, 2, '09:00', '17:30', 'Europe/London', '2023-01-01', TRUE),
(6, 3, '09:00', '17:30', 'Europe/London', '2023-01-01', TRUE),
(6, 4, '09:00', '17:30', 'Europe/London', '2023-01-01', TRUE),
(6, 5, '09:00', '17:30', 'Europe/London', '2023-01-01', TRUE),

-- Leo Thomas (Sales) - Chicago timezone
(14, 1, '08:00', '16:00', 'America/Chicago', '2023-01-01', TRUE),
(14, 2, '08:00', '16:00', 'America/Chicago', '2023-01-01', TRUE),
(14, 3, '08:00', '16:00', 'America/Chicago', '2023-01-01', TRUE),
(14, 4, '08:00', '16:00', 'America/Chicago', '2023-01-01', TRUE),
(14, 5, '08:00', '16:00', 'America/Chicago', '2023-01-01', TRUE);

-- Insert Devices
INSERT INTO devices (device_fingerprint, device_type, device_name, os_type, os_version, browser, is_corporate_managed, is_trusted) VALUES
('d1f1a2b3c4d5e6f7g8h9i0j1k2l3m4n5', 'laptop', 'John-MacBook-Pro', 'macOS', '13.0', 'Chrome/119.0', TRUE, TRUE),
('a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6', 'desktop', 'Jane-Windows-PC', 'Windows', '11', 'Edge/119.0', TRUE, TRUE),
('e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1', 'laptop', 'Bob-Lenovo-Laptop', 'Linux', 'Ubuntu 22.04', 'Firefox/120.0', TRUE, TRUE),
('b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7', 'mobile', 'Alice-iPhone', 'iOS', '17.0', 'Safari/17.0', TRUE, TRUE),
('c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8', 'laptop', 'David-MacBook-Air', 'macOS', '13.0', 'Chrome/119.0', TRUE, TRUE),
('f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2', 'desktop', 'Unknown-Device', 'Windows', '10', 'Chrome/119.0', FALSE, FALSE),
('g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3', 'mobile', 'Leo-Android', 'Android', '13', 'Chrome/119.0', FALSE, FALSE);

-- Link employees to their devices
INSERT INTO employee_devices (employee_id, device_id, is_primary, usage_count) VALUES
(1, 1, TRUE, 250),   -- John's MacBook
(2, 2, TRUE, 300),   -- Jane's PC
(3, 3, TRUE, 400),   -- Bob's Linux laptop
(4, 4, TRUE, 150),   -- Alice's iPhone
(6, 5, TRUE, 350),   -- David's MacBook
(14, 7, TRUE, 180),  -- Leo's Android
(14, 6, FALSE, 5);   -- Leo used unknown device (suspicious)

-- Insert Alert Types
INSERT INTO alert_types (alert_code, alert_name, description, severity, category, is_active, auto_escalate) VALUES
('IMP-TRAVEL-001', 'Impossible Travel Detected', 'User authenticated from two distant locations within impossible timeframe', 'high', 'impossible_travel', TRUE, TRUE),
('PRIV-ESC-001', 'Privilege Escalation', 'User role elevated to privileged level', 'high', 'privilege_escalation', TRUE, TRUE),
('PRIV-ESC-002', 'Unauthorized Access Attempt', 'User attempted to access restricted resource without permission', 'medium', 'privilege_escalation', TRUE, FALSE),
('AUDIT-TAMP-001', 'Audit Log Deletion Attempt', 'Attempted modification or deletion of audit logs', 'critical', 'audit_tampering', TRUE, TRUE),
('BRUTE-001', 'Excessive Failed Logins', 'Multiple failed authentication attempts detected', 'medium', 'brute_force', TRUE, FALSE),
('DATA-EXF-001', 'Unusual Data Volume', 'Data download/export volume significantly exceeds baseline', 'high', 'data_exfiltration', TRUE, TRUE),
('AFTER-HRS-001', 'After Hours Access', 'System access outside of normal working hours', 'low', 'after_hours', TRUE, FALSE),
('AFTER-HRS-002', 'Weekend Access to Sensitive System', 'Access to restricted system during weekend', 'medium', 'after_hours', TRUE, FALSE);

-- ============================================================
-- EVENT DATA (Simulating realistic activity patterns)
-- ============================================================

-- Normal authentication events (last 7 days)
INSERT INTO authentication_events (employee_id, device_id, event_timestamp, event_type, auth_method, result, ip_address, country_code, region, city, latitude, longitude, session_id, mfa_used) VALUES
-- John Doe - Normal pattern from San Francisco
(1, 1, CURRENT_TIMESTAMP - INTERVAL '1 day' - INTERVAL '8 hours', 'login', 'sso', 'success', '192.168.1.100', 'US', 'California', 'San Francisco', 37.7749, -122.4194, 'sess_john_001', TRUE),
(1, 1, CURRENT_TIMESTAMP - INTERVAL '2 days' - INTERVAL '8 hours', 'login', 'sso', 'success', '192.168.1.100', 'US', 'California', 'San Francisco', 37.7749, -122.4194, 'sess_john_002', TRUE),

-- Bob Wilson - Normal then IMPOSSIBLE TRAVEL (San Francisco -> NYC -> London in 4 hours)
(3, 3, CURRENT_TIMESTAMP - INTERVAL '6 hours', 'login', 'password', 'success', '10.0.1.50', 'US', 'New York', 'New York', 40.7128, -74.0060, 'sess_bob_001', TRUE),
(3, 3, CURRENT_TIMESTAMP - INTERVAL '4 hours', 'login', 'password', 'success', '51.50.100.10', 'GB', 'England', 'London', 51.5074, -0.1278, 'sess_bob_002', TRUE),

-- Leo Thomas - BRUTE FORCE ATTACK (multiple failed logins)
(14, 7, CURRENT_TIMESTAMP - INTERVAL '2 hours', 'login', 'password', 'failure', '203.0.113.45', 'US', 'Illinois', 'Chicago', 41.8781, -87.6298, NULL, FALSE),
(14, 7, CURRENT_TIMESTAMP - INTERVAL '2 hours' + INTERVAL '2 minutes', 'login', 'password', 'failure', '203.0.113.45', 'US', 'Illinois', 'Chicago', 41.8781, -87.6298, NULL, FALSE),
(14, 7, CURRENT_TIMESTAMP - INTERVAL '2 hours' + INTERVAL '4 minutes', 'login', 'password', 'failure', '203.0.113.45', 'US', 'Illinois', 'Chicago', 41.8781, -87.6298, NULL, FALSE),
(14, 7, CURRENT_TIMESTAMP - INTERVAL '2 hours' + INTERVAL '6 minutes', 'login', 'password', 'failure', '203.0.113.45', 'US', 'Illinois', 'Chicago', 41.8781, -87.6298, NULL, FALSE),
(14, 7, CURRENT_TIMESTAMP - INTERVAL '2 hours' + INTERVAL '8 minutes', 'login', 'password', 'failure', '203.0.113.45', 'US', 'Illinois', 'Chicago', 41.8781, -87.6298, NULL, FALSE),
(14, 7, CURRENT_TIMESTAMP - INTERVAL '2 hours' + INTERVAL '10 minutes', 'login', 'password', 'success', '203.0.113.45', 'US', 'Illinois', 'Chicago', 41.8781, -87.6298, 'sess_leo_001', FALSE),

-- David Miller - Normal from London
(6, 5, CURRENT_TIMESTAMP - INTERVAL '1 day' - INTERVAL '9 hours', 'login', 'sso', 'success', '51.50.200.20', 'GB', 'England', 'London', 51.5074, -0.1278, 'sess_david_001', TRUE);

-- Access logs - Normal activity
INSERT INTO access_logs (employee_id, system_id, device_id, access_timestamp, action_type, resource_accessed, access_level, result, ip_address, country_code, city, latitude, longitude, session_id) VALUES
-- Normal access
(1, 1, 1, CURRENT_TIMESTAMP - INTERVAL '1 day', 'view', '/employees/dashboard', 'read', 'success', '192.168.1.100', 'US', 'San Francisco', 37.7749, -122.4194, 'sess_john_001'),
(2, 5, 2, CURRENT_TIMESTAMP - INTERVAL '1 day', 'view', '/database/monitoring', 'admin', 'success', '192.168.1.101', 'US', 'New York', 40.7128, -74.0060, 'sess_jane_001'),

-- AFTER HOURS ACCESS by David Miller (11 PM London time on Saturday)
(6, 5, 5, CURRENT_TIMESTAMP - INTERVAL '2 days' + INTERVAL '23 hours', 'export', '/database/customer_data', 'write', 'success', '51.50.200.20', 'GB', 'London', 51.5074, -0.1278, 'sess_david_002'),

-- UNAUTHORIZED ACCESS ATTEMPT then SUCCESS (privilege escalation indicator)
(14, 5, 7, CURRENT_TIMESTAMP - INTERVAL '3 hours', 'view', '/database/admin', 'read', 'denied', '203.0.113.45', 'US', 'Chicago', 41.8781, -87.6298, 'sess_leo_001'),
(14, 5, 7, CURRENT_TIMESTAMP - INTERVAL '2 hours', 'view', '/database/admin', 'admin', 'success', '203.0.113.45', 'US', 'Chicago', 41.8781, -87.6298, 'sess_leo_002');

-- Data activity logs
INSERT INTO data_activity_logs (employee_id, system_id, activity_timestamp, activity_type, object_type, object_name, record_count, data_volume_bytes, operation_result, ip_address, session_id) VALUES
-- Normal data access
(3, 5, CURRENT_TIMESTAMP - INTERVAL '1 day', 'query', 'database_table', 'users', 100, 50000, 'success', '10.0.1.50', 'sess_bob_001'),
(9, 2, CURRENT_TIMESTAMP - INTERVAL '1 day', 'export', 'report', 'monthly_financials.xlsx', 1500, 2500000, 'success', '192.168.1.110', 'sess_grace_001'),

-- UNUSUAL LARGE DOWNLOAD by David Miller (100 MB - way above normal)
(6, 5, CURRENT_TIMESTAMP - INTERVAL '2 days' + INTERVAL '23 hours', 'download', 'database_table', 'customer_pii', 50000, 104857600, 'success', '51.50.200.20', 'sess_david_002'),

-- Suspicious export by Leo after gaining access
(14, 5, CURRENT_TIMESTAMP - INTERVAL '2 hours', 'export', 'database_table', 'sensitive_data', 10000, 52428800, 'success', '203.0.113.45', 'sess_leo_002');

-- Permission changes
INSERT INTO permission_changes (change_timestamp, change_type, target_employee_id, changed_by, role_id, old_permission_level, new_permission_level, justification, approval_required, approved_by, approval_timestamp, ip_address) VALUES
-- Normal role assignment
(CURRENT_TIMESTAMP - INTERVAL '30 days', 'role_assignment', 8, 7, 1, NULL, 'read', 'New hire onboarding', FALSE, NULL, NULL, '192.168.1.101'),

-- SUSPICIOUS PRIVILEGE ESCALATION for Leo Thomas (User -> DBA)
(CURRENT_TIMESTAMP - INTERVAL '3 hours', 'privilege_escalation', 14, 14, 4, 'read', 'admin', 'Emergency database access needed', TRUE, NULL, NULL, '203.0.113.45');

-- Insert some pre-generated alerts
INSERT INTO alerts (alert_type_id, employee_id, generated_timestamp, severity, status, confidence_score, description, evidence_summary, related_event_ids) VALUES
-- Impossible travel alert for Bob Wilson
(1, 3, CURRENT_TIMESTAMP - INTERVAL '4 hours', 'high', 'open', 92.50, 
 'Employee authenticated from New York, then London within 2 hours (3459 miles)', 
 '{"distance_miles": 3459, "time_hours": 2, "speed_mph": 1729.5, "locations": ["New York, US", "London, GB"]}'::jsonb,
 '{"auth_event_ids": [3, 4]}'::jsonb),

-- Brute force alert for Leo Thomas
(5, 14, CURRENT_TIMESTAMP - INTERVAL '2 hours', 'medium', 'investigating', 88.00,
 'Five failed login attempts within 10 minutes followed by successful login',
 '{"failure_count": 5, "time_window_minutes": 10, "ip_address": "203.0.113.45"}'::jsonb,
 '{"auth_event_ids": [5, 6, 7, 8, 9, 10]}'::jsonb),

-- Privilege escalation alert for Leo Thomas
(2, 14, CURRENT_TIMESTAMP - INTERVAL '3 hours', 'high', 'open', 95.00,
 'Self-assigned Database Administrator role without approval',
 '{"role_change": "User to DBA", "self_assigned": true, "approval_missing": true}'::jsonb,
 '{"permission_change_ids": [2]}'::jsonb),

-- Data exfiltration alert for David Miller
(6, 6, CURRENT_TIMESTAMP - INTERVAL '2 days', 'high', 'open', 87.30,
 'Downloaded 100 MB of customer PII data during weekend hours - 15x above baseline',
 '{"data_volume_mb": 100, "baseline_mb": 6.5, "z_score": 15.2, "time": "Saturday 11 PM"}'::jsonb,
 '{"data_activity_ids": [3]}'::jsonb),

-- After hours access for David Miller
(8, 6, CURRENT_TIMESTAMP - INTERVAL '2 days', 'medium', 'open', 78.50,
 'Accessed production database on Saturday at 11 PM (outside normal 9 AM - 5:30 PM schedule)',
 '{"access_time": "23:00", "scheduled_end": "17:30", "day": "Saturday", "system": "Production Database"}'::jsonb,
 '{"access_log_ids": [3]}'::jsonb);

-- Add a comment showing database is ready
COMMENT ON DATABASE company_db IS 'Enterprise Security Database - Initialized with sample data';

-- Show summary
SELECT 'Database initialized successfully!' AS status;
SELECT 'Total Employees: ' || COUNT(*) AS summary FROM employees;
SELECT 'Total Systems: ' || COUNT(*) AS summary FROM systems;
SELECT 'Total Alerts: ' || COUNT(*) AS summary FROM alerts;
SELECT 'Active High/Critical Alerts: ' || COUNT(*) AS summary FROM alerts 
WHERE status IN ('open', 'investigating') AND severity IN ('high', 'critical');