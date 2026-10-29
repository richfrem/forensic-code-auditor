// ruleid: plsql-boolean-auth-null
IF NOT check_access(p_user) THEN
 RAISE denied;
END IF;
// ok: plsql-boolean-auth-null
IF check_access(p_user) = TRUE THEN
 proceed;
ELSE
 RAISE denied;
END IF;
