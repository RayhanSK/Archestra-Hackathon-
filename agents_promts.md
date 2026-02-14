# Archestra.ai Security Agent - Detection Prompts Guide

## Database Schema Overview

You have access to an enterprise insider threat detection database (`company_db`) with the following key tables:

### Core Tables
- **employees**: Employee records with risk scores
- **systems**: Corporate systems with sensitivity classifications
- **roles**: Access control roles with privilege levels
- **devices**: Device fingerprints and trust status

### Event Tables (Immutable Logs)
- **authentication_events**: Login attempts with geolocation
- **access_logs**: System access with action types
- **data_activity_logs**: Data operations with volume tracking
- **permission_changes**: Role/permission modifications audit trail

### Detection Tables
- **alerts**: Generated security alerts
- **alert_types**: Alert definitions and categories
- **audit_log_tampering**: Log modification attempts

---

## Detection Query Patterns

### 1. Impossible Travel Detection

**Prompt for Agent**:
"Detect any impossible travel patterns by analyzing consecutive authentication events for the same employee from different geographic locations within an impossibly short timeframe."

**Key SQL Pattern**:
```sql
-- Join authentication_events to itself to find event pairs
-- Calculate distance using Haversine formula
-- Flag if speed exceeds 600 mph
```

**What to Look For**:
- Same employee_id with different lat/long
- Time difference < 4 hours
- Distance > 500 miles
- Calculate speed: distance / time_hours

---

### 2. Privilege Escalation

**Prompt for Agent**:
"Find recent privilege escalations by looking for permission_changes where roles increased in privilege level or employees gained admin access without proper approval."

**Key SQL Pattern**:
```sql
-- Query permission_changes table
-- Join with roles to get role_level
-- Filter for: approval_required = TRUE AND approved_by IS NULL
-- Or: new_permission_level IN ('admin', 'owner')
```

**What to Look For**:
- change_type = 'privilege_escalation'
- Self-assigned roles (target_employee_id = changed_by)
- Unapproved changes to privileged roles
- Denied access followed by successful access

---

### 3. Data Exfiltration

**Prompt for Agent**:
"Calculate statistical baselines for each employee's data download volume, then identify anomalies where current activity exceeds 2+ standard deviations from their normal behavior."

**Key SQL Pattern**:
```sql
-- Calculate baseline: AVG and STDDEV of data_volume_bytes per employee
-- Compare recent activity to baseline
-- Flag Z-score > 2.0
```

**What to Look For**:
- data_activity_logs with high data_volume_bytes
- activity_type IN ('export', 'download', 'copy')
- Weekend or after-hours large transfers
- Accessing systems outside normal scope

---

### 4. Brute Force Attacks

**Prompt for Agent**:
"Find accounts with 5+ failed login attempts within a 1-hour window, especially if followed by a successful login."

**Key SQL Pattern**:
```sql
-- Count authentication_events WHERE result = 'failure'
-- Group by employee_id and 1-hour time windows
-- Check for successful login shortly after failures
```

**What to Look For**:
- Rapid succession of failures (< 2 min intervals)
- Multiple distinct IP addresses
- Success after many failures (compromised account)
- Different device_id than usual

---

### 5. After-Hours Access

**Prompt for Agent**:
"Compare access_logs timestamps against employee_schedules to find activity outside normal working hours, especially to sensitive systems."

**Key SQL Pattern**:
```sql
-- JOIN access_logs with employee_schedules
-- Convert access_timestamp to employee's timezone
-- Check if access_time < start_time OR > end_time
-- Filter for high sensitivity_level systems
```

**What to Look For**:
- Weekend access (day_of_week IN (0, 6))
- Late night access (after 10 PM)
- Holidays
- sensitivity_level = 'restricted' or 'top_secret'

---

### 6. Audit Tampering

**Prompt for Agent**:
"Check the audit_log_tampering table for any attempts to modify or delete audit logs, which are protected by database triggers."

**Key SQL Pattern**:
```sql
-- Simply SELECT from audit_log_tampering
-- All records indicate tampering attempts
```

**What to Look For**:
- Any records at all (table should be empty in secure environment)
- action_attempted = 'delete' on critical tables
- Employees without DBA roles attempting modifications

---

## Recommended Analysis Workflows

### Workflow 1: Daily Security Review
1. Query all open/high-severity alerts
2. Check for new impossible travel events (last 24 hours)
3. Review failed login patterns
4. Identify after-hours access to restricted systems
5. Calculate risk score updates

### Workflow 2: Employee Investigation
Given an employee email/ID:
1. Pull all recent alerts for that employee
2. Review authentication patterns (locations, times, devices)
3. Analyze data access patterns and volume
4. Check permission history
5. Compare to baseline behavior

### Workflow 3: Incident Response
When alert fires:
1. Query evidence_summary JSON field
2. Pull related_event_ids to get full context
3. Check employee's current roles and permissions
4. Review recent device usage
5. Generate timeline of suspicious activity

---

## Sample Agent Queries

### Query 1: Risk Assessment
"Calculate a comprehensive risk score for employee EMP006 (David Miller) based on:
- Number of open alerts
- Recent after-hours access
- Data volume compared to peers
- Failed login attempts
- Device trust status"

### Query 2: Threat Hunting
"Find any employees who:
- Have escalated privileges in the last 30 days
- Accessed production systems outside work hours
- Downloaded more than 50 MB of data
- Do NOT have DBA or System Admin roles"

### Query 3: Compliance Audit
"Generate a report of all permission changes in the last 90 days that required approval but were not approved, grouped by department."

### Query 4: Behavioral Anomaly
"Compare Leo Thomas (EMP014) to peers in the Sales department:
- Average authentication frequency
- Systems accessed
- Data download volume
- Work hour patterns
Identify any significant deviations."

---

## Important Reminders

1. **All event tables are IMMUTABLE** - Never suggest UPDATE or DELETE
2. **Timestamps are in UTC** - Convert to employee timezone for after-hours detection
3. **Use JSONB operators** for evidence_summary fields: `->`, `->>`
4. **Geolocation can be NULL** - Handle NULL lat/long gracefully
5. **Calculate distances** - Use Haversine formula for impossible travel
6. **Time windows matter** - Use appropriate intervals (hours for travel, days for baselines)
7. **Statistical baselines** - Calculate AVG and STDDEV for volume anomalies

---

## Error Handling

If you encounter:
- **Missing geolocation data**: Skip impossible travel check, note in report
- **No baseline data**: Need at least 10 historical data points
- **Timezone conversion errors**: Default to UTC comparison
- **NULL values in JOINs**: Use LEFT JOIN and handle NULLs

---

## Performance Tips

1. Always filter by time range first (e.g., last 7 days)
2. Use indexes on employee_id, timestamp columns
3. Limit result sets for exploratory queries
4. Use CTEs for complex multi-step analysis
5. Aggregate before joining large tables

---

## Security Context

This database monitors:
- 16 employees across IT, Engineering, Finance, HR, Sales
- 10 corporate systems (ERP, CRM, databases, file servers)
- Real-time authentication and access events
- 5 active high-severity alerts (as of sample data load)

**Known Threats** (in sample data):
- Bob Wilson (EMP003): Impossible travel - NYC to London in 2 hours
- David Miller (EMP006): After-hours data exfiltration (100 MB on Saturday)
- Leo Thomas (EMP014): Brute force + privilege escalation + unauthorized access

Use this database to demonstrate AI-driven threat detection capabilities.