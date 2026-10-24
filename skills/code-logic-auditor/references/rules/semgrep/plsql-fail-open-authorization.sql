// Semgrep generic engine tests using '//' comments

// ruleid: plsql-auth-function-when-others-allow
FUNCTION chk_user_access(p_user_id IN NUMBER, p_doc_id IN NUMBER) RETURN BOOLEAN IS
  v_role VARCHAR2(50);
BEGIN
  SELECT role INTO v_role FROM doc_perms WHERE user_id = p_user_id AND doc_id = p_doc_id;
  RETURN v_role = 'ADMIN';
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('Error reading perms: ' || SQLERRM);
    RETURN TRUE;
END;
/

// ok: plsql-auth-function-when-others-allow
FUNCTION chk_user_access_safe(p_user_id IN NUMBER, p_doc_id IN NUMBER) RETURN BOOLEAN IS
  v_role VARCHAR2(50);
BEGIN
  SELECT role INTO v_role FROM doc_perms WHERE user_id = p_user_id AND doc_id = p_doc_id;
  RETURN v_role = 'ADMIN';
EXCEPTION
  WHEN OTHERS THEN
    RETURN FALSE;
END;
/

// ruleid: plsql-vpd-policy-empty-predicate
FUNCTION vpd_tenant_policy(p_schema VARCHAR2, p_tab VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN 'tenant_id = SYS_CONTEXT(''app_ctx'', ''tenant_id'')';
EXCEPTION
  WHEN OTHERS THEN
    RETURN NULL;
END;
/

// ok: plsql-vpd-policy-empty-predicate
FUNCTION vpd_tenant_policy_safe(p_schema VARCHAR2, p_tab VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN 'tenant_id = SYS_CONTEXT(''app_ctx'', ''tenant_id'')';
EXCEPTION
  WHEN OTHERS THEN
    RETURN '1=0';
END;
/

// ruleid: plsql-null-expands-scope-filter
SELECT * FROM permits WHERE (:p_tenant_id IS NULL OR tenant_id = :p_tenant_id);

// ok: plsql-null-expands-scope-filter
SELECT * FROM permits WHERE tenant_id = :p_tenant_id;
