# Independent synthetic policy baseline

This is an authored benchmark oracle representing owner-approved policy, not a real approval.
It is maintained independently from evaluator code and configuration rows.

## P-APPROVE

A clerk may navigate Claims but must not approve a pending claim in north.
An approver may approve pending claims in north. Other scopes/states are not specified.

## E-RELIEF

Principal relief-clerk may approve pending north claims during synthetic time [10,20).
The API service may carry that delegation only for the same principal, operation and scope;
a shared service connection alone does not delegate this authority.
