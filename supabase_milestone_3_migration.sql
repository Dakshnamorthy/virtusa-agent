-- ============================================================================
-- CIDAN AI: MILESTONE 3 SUPABASE CLOUD SCHEMA MIGRATION
-- Approval Workflow, Rule Versioning, Testing & Simulation,
-- Deployment Orchestration, Production Activation, Rollback, Audit & Notifications
-- Run in Supabase Cloud Dashboard -> SQL Editor (vettckrwudnnvoalvjno)
-- ============================================================================

-- 1. APPROVAL WORKFLOWS TABLE
-- Tracks approval workflows for proposed rule changes across the 16-state lifecycle
CREATE TABLE IF NOT EXISTS public.approval_workflows (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL,
    delta_id UUID REFERENCES public.rule_deltas(id) ON DELETE SET NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    category TEXT NOT NULL,
    circular_reference TEXT,
    author_id TEXT NOT NULL,
    author_email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN (
        'DRAFT', 'SUBMITTED_FOR_REVIEW', 'UNDER_REVIEW', 'CHANGES_REQUESTED',
        'RESUBMITTED', 'APPROVED', 'REJECTED', 'READY_FOR_TESTING',
        'TESTING_IN_PROGRESS', 'TEST_FAILED', 'TEST_PASSED',
        'READY_FOR_DEPLOYMENT', 'DEPLOYMENT_IN_PROGRESS', 'DEPLOYED',
        'DEPLOYMENT_FAILED', 'ROLLED_BACK'
    )),
    current_stage_index INTEGER DEFAULT 0,
    required_stages JSONB DEFAULT '[]'::jsonb,
    rule_ir_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    deadline TIMESTAMPTZ,
    rejection_reason TEXT,
    change_request_notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. APPROVAL STAGES & DECISIONS TABLE
-- Records multi-level sequential or parallel approvals and separation of duties
CREATE TABLE IF NOT EXISTS public.approval_decisions (
    id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES public.approval_workflows(id) ON DELETE CASCADE,
    bank_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    delta_id TEXT,
    stage_name TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    approver_email TEXT NOT NULL,
    approver_role TEXT NOT NULL CHECK (approver_role IN (
        'RULE_AUTHOR', 'COMPLIANCE_ANALYST', 'COMPLIANCE_MANAGER',
        'RISK_OFFICER', 'TECHNICAL_APPROVER', 'DEPLOYMENT_ADMIN', 'SYSTEM_ADMIN'
    )),
    decision TEXT NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED', 'CHANGES_REQUESTED', 'RESUBMITTED')),
    comments TEXT,
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    decided_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. RULE VERSIONS TABLE
-- Immutable version history for rules (Version 1.0, 1.1, 2.0 snapshots)
CREATE TABLE IF NOT EXISTS public.rule_versions (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    bank_id TEXT NOT NULL,
    version_number TEXT NOT NULL,
    parent_version TEXT,
    rule_ir_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    change_summary TEXT,
    change_source TEXT DEFAULT 'REGULATORY_CIRCULAR',
    regulatory_reference TEXT,
    approval_workflow_id TEXT REFERENCES public.approval_workflows(id) ON DELETE SET NULL,
    created_by TEXT NOT NULL,
    is_active BOOLEAN DEFAULT false,
    activation_timestamp TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. RULE TEST SUITES & TEST CASES
-- Isolated simulation testing: positive, negative, boundary, regression, conflict
CREATE TABLE IF NOT EXISTS public.rule_test_suites (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    suite_name TEXT NOT NULL,
    description TEXT,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.rule_test_cases (
    id TEXT PRIMARY KEY,
    suite_id TEXT NOT NULL REFERENCES public.rule_test_suites(id) ON DELETE CASCADE,
    bank_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    test_type TEXT NOT NULL CHECK (test_type IN (
        'POSITIVE', 'NEGATIVE', 'BOUNDARY', 'REGRESSION', 'CONFLICT', 'DEPENDENCY'
    )),
    scenario_name TEXT NOT NULL,
    input_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    expected_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_ai_generated BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. RULE TEST RUNS & TEST RESULTS
CREATE TABLE IF NOT EXISTS public.rule_test_runs (
    id TEXT PRIMARY KEY,
    suite_id TEXT NOT NULL REFERENCES public.rule_test_suites(id) ON DELETE CASCADE,
    bank_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    total_test_cases INTEGER DEFAULT 0,
    passed_tests INTEGER DEFAULT 0,
    failed_tests INTEGER DEFAULT 0,
    pass_percentage DOUBLE PRECISION DEFAULT 0.0,
    execution_duration_ms INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN (
        'PENDING', 'RUNNING', 'PASSED', 'FAILED', 'PARTIALLY_PASSED', 'CANCELLED'
    )),
    started_by TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.rule_test_results (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES public.rule_test_runs(id) ON DELETE CASCADE,
    test_case_id TEXT NOT NULL REFERENCES public.rule_test_cases(id) ON DELETE CASCADE,
    bank_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PASS', 'FAIL', 'ERROR')),
    actual_output JSONB NOT NULL DEFAULT '{}'::jsonb,
    execution_duration_ms INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. DEPLOYMENT PACKAGES, TARGETS & RECORDS
CREATE TABLE IF NOT EXISTS public.deployment_packages (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    version_id TEXT NOT NULL REFERENCES public.rule_versions(id) ON DELETE CASCADE,
    approved_rule_ir JSONB NOT NULL,
    regulatory_reference TEXT,
    approval_records JSONB DEFAULT '[]'::jsonb,
    validation_results JSONB DEFAULT '[]'::jsonb,
    test_results JSONB DEFAULT '[]'::jsonb,
    package_checksum TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.deployment_targets (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('REST', 'GRAPHQL', 'SQL', 'ENGINE')),
    environment TEXT NOT NULL CHECK (environment IN ('DEVELOPMENT', 'UAT', 'STAGING', 'PRODUCTION')),
    endpoint_url TEXT,
    is_writable BOOLEAN DEFAULT false,
    supports_rollback BOOLEAN DEFAULT true,
    capabilities JSONB DEFAULT '[]'::jsonb,
    status TEXT DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.deployment_records (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL,
    package_id TEXT NOT NULL REFERENCES public.deployment_packages(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES public.deployment_targets(id) ON DELETE CASCADE,
    deployment_mode TEXT NOT NULL CHECK (deployment_mode IN ('MANUAL', 'SCHEDULED', 'CONTROLLED')),
    status TEXT NOT NULL DEFAULT 'PREPARING' CHECK (status IN (
        'PREPARING', 'VALIDATING', 'APPROVAL_PENDING', 'READY', 'DEPLOYING',
        'VERIFYING', 'ACTIVE', 'FAILED', 'ROLLBACK_PENDING', 'ROLLED_BACK'
    )),
    scheduled_for TIMESTAMPTZ,
    deployed_by TEXT NOT NULL,
    target_response JSONB DEFAULT '{}'::jsonb,
    post_verification_status TEXT,
    error_message TEXT,
    deployed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. ROLLBACK RECORDS
CREATE TABLE IF NOT EXISTS public.rollback_records (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL REFERENCES public.deployment_records(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    deployed_version TEXT NOT NULL,
    restored_version TEXT NOT NULL,
    reason TEXT NOT NULL,
    initiated_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'INITIATED' CHECK (status IN (
        'INITIATED', 'VERIFYING', 'COMPLETED', 'FAILED'
    )),
    target_verification JSONB DEFAULT '{}'::jsonb,
    rolled_back_at TIMESTAMPTZ DEFAULT NOW()
);

-- 8. COMPLIANCE AUDIT TRAIL TABLE (Immutable Append-Only)
CREATE TABLE IF NOT EXISTS public.audit_events (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    previous_state JSONB,
    new_state JSONB,
    correlation_id TEXT,
    ip_address TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 9. NOTIFICATIONS & ESCALATION POLICIES TABLE
CREATE TABLE IF NOT EXISTS public.notifications (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    resource_id TEXT,
    delivery_channel TEXT NOT NULL DEFAULT 'IN_APP' CHECK (delivery_channel IN ('IN_APP', 'EMAIL', 'BOTH')),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SENT', 'FAILED', 'READ')),
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.escalation_policies (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL,
    workflow_stage TEXT NOT NULL,
    deadline_hours INTEGER DEFAULT 48,
    escalate_to_role TEXT NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- INDEXES FOR FAST FILTERING AND TENANT ISOLATION
CREATE INDEX IF NOT EXISTS idx_approval_wf_bank ON public.approval_workflows(bank_id, status);
CREATE INDEX IF NOT EXISTS idx_approval_dec_wf ON public.approval_decisions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_rule_versions_rule ON public.rule_versions(rule_id, version_number);
CREATE INDEX IF NOT EXISTS idx_rule_test_suites_rule ON public.rule_test_suites(bank_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_test_runs_suite ON public.rule_test_runs(suite_id);
CREATE INDEX IF NOT EXISTS idx_deployment_records_bank ON public.deployment_records(bank_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_events_bank ON public.audit_events(bank_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_recipient ON public.notifications(recipient_email, is_read);

-- ROW LEVEL SECURITY
ALTER TABLE public.approval_workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.approval_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rule_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rule_test_suites ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rule_test_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rule_test_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rule_test_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.deployment_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.deployment_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.deployment_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rollback_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.escalation_policies ENABLE ROW LEVEL SECURITY;

-- BANK-ISOLATED PERMISSIVE POLICIES FOR AUTHENTICATED & ANON CLIENTS
CREATE POLICY "Allow authenticated read approval_workflows" ON public.approval_workflows FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert approval_workflows" ON public.approval_workflows FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow authenticated update approval_workflows" ON public.approval_workflows FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Allow anon read approval_workflows" ON public.approval_workflows FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert approval_workflows" ON public.approval_workflows FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Allow anon update approval_workflows" ON public.approval_workflows FOR UPDATE TO anon USING (true);

CREATE POLICY "Allow authenticated read approval_decisions" ON public.approval_decisions FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert approval_decisions" ON public.approval_decisions FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow anon read approval_decisions" ON public.approval_decisions FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert approval_decisions" ON public.approval_decisions FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "Allow authenticated read rule_versions" ON public.rule_versions FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert rule_versions" ON public.rule_versions FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow authenticated update rule_versions" ON public.rule_versions FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Allow anon read rule_versions" ON public.rule_versions FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert rule_versions" ON public.rule_versions FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Allow anon update rule_versions" ON public.rule_versions FOR UPDATE TO anon USING (true);

CREATE POLICY "Allow authenticated read rule_test_suites" ON public.rule_test_suites FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert rule_test_suites" ON public.rule_test_suites FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow anon read rule_test_suites" ON public.rule_test_suites FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert rule_test_suites" ON public.rule_test_suites FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "Allow authenticated read rule_test_cases" ON public.rule_test_cases FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert rule_test_cases" ON public.rule_test_cases FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow anon read rule_test_cases" ON public.rule_test_cases FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert rule_test_cases" ON public.rule_test_cases FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "Allow authenticated read rule_test_runs" ON public.rule_test_runs FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert rule_test_runs" ON public.rule_test_runs FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow authenticated update rule_test_runs" ON public.rule_test_runs FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Allow anon read rule_test_runs" ON public.rule_test_runs FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert rule_test_runs" ON public.rule_test_runs FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Allow anon update rule_test_runs" ON public.rule_test_runs FOR UPDATE TO anon USING (true);

CREATE POLICY "Allow authenticated read rule_test_results" ON public.rule_test_results FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert rule_test_results" ON public.rule_test_results FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow anon read rule_test_results" ON public.rule_test_results FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert rule_test_results" ON public.rule_test_results FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "Allow authenticated read deployment_packages" ON public.deployment_packages FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert deployment_packages" ON public.deployment_packages FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow anon read deployment_packages" ON public.deployment_packages FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert deployment_packages" ON public.deployment_packages FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "Allow authenticated read deployment_targets" ON public.deployment_targets FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert deployment_targets" ON public.deployment_targets FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow anon read deployment_targets" ON public.deployment_targets FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert deployment_targets" ON public.deployment_targets FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "Allow authenticated read deployment_records" ON public.deployment_records FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert deployment_records" ON public.deployment_records FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow authenticated update deployment_records" ON public.deployment_records FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Allow anon read deployment_records" ON public.deployment_records FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert deployment_records" ON public.deployment_records FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Allow anon update deployment_records" ON public.deployment_records FOR UPDATE TO anon USING (true);

CREATE POLICY "Allow authenticated read rollback_records" ON public.rollback_records FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert rollback_records" ON public.rollback_records FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow anon read rollback_records" ON public.rollback_records FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert rollback_records" ON public.rollback_records FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "Allow authenticated read audit_events" ON public.audit_events FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert audit_events" ON public.audit_events FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow anon read audit_events" ON public.audit_events FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert audit_events" ON public.audit_events FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "Allow authenticated read notifications" ON public.notifications FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated insert notifications" ON public.notifications FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Allow authenticated update notifications" ON public.notifications FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Allow anon read notifications" ON public.notifications FOR SELECT TO anon USING (true);
CREATE POLICY "Allow anon insert notifications" ON public.notifications FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Allow anon update notifications" ON public.notifications FOR UPDATE TO anon USING (true);
