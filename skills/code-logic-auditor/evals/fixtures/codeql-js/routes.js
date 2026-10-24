const express = require("express");
const app = express();

app.post("/orders/:id/status", async (req, res) => {
  const order = await Order.findById(req.params.id);
  order.status = req.body.status; // EXPECT: unguarded-state-transition
  await order.save();
  res.sendStatus(204);
});

app.post("/orders/:id/status-orm", async (req, res) => {
  await prisma.order.update({ where: { id: req.params.id }, data: { status: req.body.status } }); // EXPECT
  res.sendStatus(204);
});

app.post("/orders/:id/status-guarded", async (req, res) => {
  const order = await Order.findById(req.params.id);
  const next = req.body.status;
  if (canTransition(order.status, next)) {
    order.status = next; // OK
    await order.save();
  }
  res.sendStatus(204);
});

app.post("/orders/:id/status-throw", async (req, res) => {
  const order = await Order.findById(req.params.id);
  const next = req.body.status;
  if (!isValidTransition(order.status, next)) throw new Error("bad transition");
  order.status = next; // OK
  await order.save();
  res.sendStatus(204);
});

app.post("/orders/:id/cancel", async (req, res) => {
  const order = await Order.findById(req.params.id);
  order.status = "CANCELLED"; // OK: constant, not remote
  await order.save();
  res.sendStatus(204);
});
