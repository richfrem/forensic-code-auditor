class Wallet
{
    void Direct(int id, decimal amt)
    {
        // ruleid: csharp-check-then-act-balance
        if (svc.GetBalance(id) >= amt) { Log(); svc.DeductBalance(id, amt); }
    }

    void ViaLocal(int id, decimal amt)
    {
        // ruleid: csharp-check-then-act-balance
        var bal = repo.GetAvailable(id);
        if (bal >= amt) { repo.Withdraw(id, amt); }
    }

    void DefaultScopeStillRacy(int id, decimal amt)
    {
        using (var tx = new TransactionScope())
        {
            // ruleid: csharp-check-then-act-balance
            if (svc.GetBalance(id) >= amt) { svc.DeductBalance(id, amt); }
            tx.Complete();
        }
    }

    void Atomic(int id, decimal amt)
    {
        // ok: csharp-check-then-act-balance
        var rows = db.Execute("UPDATE acct SET bal = bal - @a WHERE id = @id AND bal >= @a", new { a = amt, id });
        if (rows == 0) throw new InsufficientFunds();
    }

    void Unrelated(int id)
    {
        // ok: csharp-check-then-act-balance
        if (svc.GetName(id) != null) { svc.Rename(id, "x"); }
    }
}
