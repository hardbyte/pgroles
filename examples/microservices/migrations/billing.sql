CREATE TABLE IF NOT EXISTS billing.customers (
  id integer generated always as identity primary key,
  email text not null unique
);

CREATE TABLE IF NOT EXISTS billing.invoices (
  id integer generated always as identity primary key,
  customer_id integer not null references billing.customers(id),
  amount_cents integer not null check (amount_cents > 0),
  status text not null default 'open'
);

