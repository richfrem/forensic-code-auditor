const express = require("express");
const app = express();

app.post("/orders/:id/status", async (req, res) => {
  const order = await Order.findById(req.params.id);
  order.status = req.body.status; // EXPECT: unguarded-state-transition
  await order.save();
  res.sendStatus(204);
});

app.post("/orders/:id/status-orm", async (req, res) => {
  await prisma.order.update({ where: { id: req.params.id }, data: { status: req.body.status } }); // EXPECT: unguarded-state-transition
  res.sendStatus(204);
});

app.post("/orders/:id/status-guarded", async (req, res) => {
  const order = await Order.findById(req.params.id);
  const next = req.body.status;
  if (canTransition(order.status, next)) {
    order.status = next; // OK: guarded path
    await order.save();
  }
  res.sendStatus(204);
});

app.post("/orders/:id/status-throw", async (req, res) => {
  const order = await Order.findById(req.params.id);
  const next = req.body.status;
  if (!isValidTransition(order.status, next)) throw new Error("bad transition");
  order.status = next; // OK: guarded path
  await order.save();
  res.sendStatus(204);
});

app.post("/orders/:id/cancel", async (req, res) => {
  const order = await Order.findById(req.params.id);
  // Constant write: outside untrusted taint propagation, but may still violate
  // lifecycle invariants if order is in a terminal state (e.g. SHIPPED/FULFILLED).
  order.status = "CANCELLED"; // OK (taint query); SUSPECTED/NON LIQUET (lifecycle audit)
  await order.save();
  res.sendStatus(204);
});

app.post("/orders/:id/status-wrong-object", async (req, res) => {
  const orderA = await Order.findById(req.params.id);
  const orderB = await Order.findById(req.body.otherId);
  const next = req.body.status;
  // Flawed guard: checks orderA transition, but mutates orderB!
  if (canTransition(orderA.status, next)) {
    orderB.status = next; // EXPECT: wrong-object guard bypass
    await orderB.save();
  }
  res.sendStatus(204);
});


app.post("/orders/:id/enum-only", async (req,res) => {
  const order = await Order.findById(req.params.id);
  if (validateState(req.body.status)) order.status = req.body.status;
});
app.post("/orders/:id/noop-guard", async (req,res) => {
  const order = await Order.findById(req.params.id);
  function canTransition() { return true; }
  if (canTransition(order.status, req.body.status)) order.status = req.body.status;
});
app.post("/orders/:id/assign", async (req,res) => {
  const order = await Order.findById(req.params.id);
  Object.assign(order, req.body);
});
app.post("/orders/:id/body", async (req,res) => {
  await prisma.order.update({where: {id:req.params.id}, data:req.body});
});
app.post("/orders/:id/setter", async (req,res) => {
  const order = await Order.findById(req.params.id);
  order.setStatus(req.body.status);
});
app.post("/orders/:id/raw", async (req,res) => {
  db.query("UPDATE orders SET status=? WHERE id=?", [req.body.status,req.params.id]);
});
