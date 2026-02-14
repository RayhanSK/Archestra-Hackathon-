-- ============================================================
-- TEST QUERIES FOR MCP SERVER VALIDATION
-- Use these to verify the agent can access and query the database
-- ============================================================

-- Test 1: Basic employee query
SELECT 
    employee_number,
    email,
    first_name,
    last_name,
    department,
    employment_status,
    risk_score
FROM employees
WHERE employment_status = 'active'
ORDER BY risk_score DESC
LIMIT 10;

-- Test 2: Active high-severity alerts
SELECT 
    a.alert_id,
    a.generated_timestamp,
    at.alert_name,
    at.category,
    a.severity,
    e.email AS employee_email,
    a.description,
    a.confidence_score
FROM alerts a
JOIN alert_types at ON a.alert_type_id = at.alert_type_id
JOIN employees e ON a.employee_id = e.employee_id
WHERE a.status IN ('open', 'investigating')
    AND a.severity IN ('high', 'critical')
ORDER BY a.generated_timestamp DESC;

-- Test 3: Recent authentication events
SELECT 
    e.email,
    ae.event_timestamp,
    ae.event_type,
    ae.result,
    ae.city,
    ae.country_code,
    ae.ip_address
FROM authentication_events ae
JOIN employees e ON ae.employee_id = e.employee_id
ORDER BY ae.event_timestamp DESC
LIMIT 20;

-- Test 4: Systems by sensitivity level
SELECT 
    system_name,
    system_type,
    sensitivity_level,
    requires_mfa,
    is_production
FROM systems
ORDER BY 
    CASE sensitivity_level
        WHEN 'top_secret' THEN 1
        WHEN 'restricted' THEN 2
        WHEN 'confidential' THEN 3
        WHEN 'internal' THEN 4
        WHEN 'public' THEN 5
    END;

-- Test 5: Employee roles and permissions
SELECT 
    e.email,
    e.department,
    r.role_name,
    r.role_level,
    r.is_privileged
FROM employees e
JOIN employee_roles er ON e.employee_id = er.employee_id
JOIN roles r ON er.role_id = r.role_id
WHERE er.is_active = TRUE
    AND e.employment_status = 'active'
ORDER BY r.role_level DESC;

-- Test 6: Recent data activity with volume
SELECT 
    e.email,
    s.system_name,
    dal.activity_timestamp,
    dal.activity_type,
    dal.object_name,
    ROUND((dal.data_volume_bytes / 1024.0 / 1024.0)::numeric, 2) AS volume_mb,
    dal.record_count
FROM data_activity_logs dal
JOIN employees e ON dal.employee_id = e.employee_id
JOIN systems s ON dal.system_id = s.system_id
ORDER BY dal.data_volume_bytes DESC
LIMIT 10;

-- Test 7: Failed login attempts (last 24 hours)
SELECT 
    e.email,
    COUNT(*) AS failure_count,
    COUNT(DISTINCT ae.ip_address) AS distinct_ips,
    MIN(ae.event_timestamp) AS first_failure,
    MAX(ae.event_timestamp) AS last_failure
FROM authentication_events ae
JOIN employees e ON ae.employee_id = e.employee_id
WHERE ae.result = 'failure'
    AND ae.event_timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
GROUP BY e.email
HAVING COUNT(*) >= 3
ORDER BY failure_count DESC;

-- Test 8: Permission changes requiring approval
SELECT 
    pc.change_timestamp,
    target.email AS target_employee,
    changer.email AS changed_by,
    pc.change_type,
    r.role_name,
    pc.old_permission_level,
    pc.new_permission_level,
    pc.approval_required,
    approver.email AS approved_by
FROM permission_changes pc
JOIN employees target ON pc.target_employee_id = target.employee_id
JOIN employees changer ON pc.changed_by = changer.employee_id
LEFT JOIN roles r ON pc.role_id = r.role_id
LEFT JOIN employees approver ON pc.approved_by = approver.employee_id
WHERE pc.approval_required = TRUE
ORDER BY pc.change_timestamp DESC
LIMIT 10;

-- Test 9: After-hours access detection (sample)
SELECT 
    e.email,
    al.access_timestamp,
    s.system_name,
    al.action_type,
    EXTRACT(DOW FROM al.access_timestamp) AS day_of_week,
    TO_CHAR(al.access_timestamp, 'HH24:MI:SS') AS access_time
FROM access_logs al
JOIN employees e ON al.employee_id = e.employee_id
JOIN systems s ON al.system_id = s.system_id
WHERE EXTRACT(DOW FROM al.access_timestamp) IN (0, 6)  -- Weekend
    OR EXTRACT(HOUR FROM al.access_timestamp) NOT BETWEEN 8 AND 18  -- Outside 8 AM - 6 PM
ORDER BY al.access_timestamp DESC
LIMIT 20;

-- Test 10: High-risk employees with recent activity
SELECT 
    e.email,
    e.department,
    e.risk_score,
    e.last_risk_assessment_date,
    COUNT(DISTINCT al.access_log_id) AS recent_access_count,
    COUNT(DISTINCT a.alert_id) AS open_alerts
FROM employees e
LEFT JOIN access_logs al 
    ON e.employee_id = al.employee_id 
    AND al.access_timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days'
LEFT JOIN alerts a 
    ON e.employee_id = a.employee_id 
    AND a.status IN ('open', 'investigating')
WHERE e.employment_status = 'active'
GROUP BY e.employee_id, e.email, e.department, e.risk_score, e.last_risk_assessment_date
HAVING e.risk_score > 10
ORDER BY e.risk_score DESC;