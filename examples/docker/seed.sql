-- Enough of a schema to make the blast radius interesting: signups has
-- children, and the children have children, all wired with ON DELETE CASCADE.
--
-- `DELETE FROM signups` therefore takes 88,412 rows across three tables, only
-- one of which the statement mentions.

CREATE TABLE signups (
  id         serial PRIMARY KEY,
  email      text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE orders (
  id        serial PRIMARY KEY,
  signup_id int NOT NULL REFERENCES signups(id) ON DELETE CASCADE,
  total     numeric(10,2) NOT NULL
);

CREATE TABLE order_items (
  id       serial PRIMARY KEY,
  order_id int NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  sku      text NOT NULL
);

INSERT INTO signups (email)
SELECT 'user' || i || '@example.com' FROM generate_series(1, 8412) i;

INSERT INTO orders (signup_id, total)
SELECT (random() * 8411 + 1)::int, (random() * 500)::numeric(10,2)
FROM generate_series(1, 20000);

INSERT INTO order_items (order_id, sku)
SELECT (random() * 19999 + 1)::int, 'SKU-' || (random() * 999)::int
FROM generate_series(1, 60000);

-- Without this, pg_class.reltuples is zero and SupaSafe has nothing to
-- estimate from.
ANALYZE;
