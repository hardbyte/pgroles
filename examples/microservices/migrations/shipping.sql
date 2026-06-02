CREATE TABLE IF NOT EXISTS shipping.shipments (
  id integer generated always as identity primary key,
  billing_invoice_id integer not null references billing.invoices(id),
  destination text not null,
  status text not null default 'pending'
);
