// Semgrep test annotations use "//" because the generic engine ignores "--" comments.
// ok: plsql-autonomous-transaction-business-dml
CREATE OR REPLACE PROCEDURE log_audit(p_msg VARCHAR2) IS
  PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
  INSERT INTO audit_log(msg) VALUES (p_msg);
  COMMIT;
END;
/

// ruleid: plsql-autonomous-transaction-business-dml
CREATE OR REPLACE PROCEDURE insert_payment(p_id NUMBER, p_amt NUMBER) IS
  PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
  INSERT INTO payment_ledger(id, amount) VALUES (p_id, p_amt);
  COMMIT;
END;
/

// ruleid: plsql-autonomous-transaction-business-dml
CREATE OR REPLACE PROCEDURE settle(p_id NUMBER) IS
  PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
  UPDATE ledger SET status = 'SETTLED' WHERE id = p_id;
  COMMIT;
END;
/

// ruleid: plsql-autonomous-transaction-in-trigger
CREATE OR REPLACE TRIGGER trg_orders_au
AFTER UPDATE ON orders FOR EACH ROW
DECLARE
  PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
  INSERT INTO order_hist(id) VALUES (:NEW.id);
  COMMIT;
END;
/
