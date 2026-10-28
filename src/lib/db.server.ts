import "@tanstack/react-start/server-only";
import postgres from "postgres";

// Conexão com o Postgres do Supabase. Use a "Connection string" do painel do Supabase
// (Project Settings → Database → Connection pooler / Transaction) na variável SUPABASE_DB_URL.
function connectionString() {
  const candidates = [process.env.SUPABASE_DB_URL, process.env.SUPABASE_DATABASE_URL, process.env.DATABASE_URL];
  const url = candidates.find((value) => value?.startsWith("postgres"));
  if (!url) throw new Error("Banco de dados não configurado: defina a variável SUPABASE_DB_URL com a connection string do Supabase.");
  return url;
}

let client: postgres.Sql | undefined;
let ready: Promise<void> | undefined;

const now = "to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')";
const recordTables = [
  "occurrences", "predictions", "audits", "contests", "reports", "notifications", "patrols",
  "recommendations", "ai_decisions", "bias_alerts", "mitigations", "models", "data_quality",
];

async function migrate(sql: postgres.Sql) {
  await sql.unsafe(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      role TEXT NOT NULL CHECK (role IN ('citizen', 'institutional')),
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      cpf TEXT UNIQUE,
      birth_date TEXT,
      phone TEXT,
      postal_code TEXT,
      state TEXT NOT NULL DEFAULT 'BA',
      city TEXT NOT NULL DEFAULT 'Salvador',
      neighborhood TEXT,
      address TEXT,
      institution TEXT,
      functional_id TEXT UNIQUE,
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      location_consent BOOLEAN NOT NULL DEFAULT false,
      institutional_type TEXT,
      created_at TEXT NOT NULL DEFAULT ${now}
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT ${now}
    );
    CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS user_accessibility_preferences (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      text_scale INTEGER NOT NULL DEFAULT 100 CHECK (text_scale BETWEEN 80 AND 140),
      high_contrast BOOLEAN NOT NULL DEFAULT false,
      reduce_motion BOOLEAN NOT NULL DEFAULT false,
      screen_reader BOOLEAN NOT NULL DEFAULT true,
      updated_at TEXT NOT NULL DEFAULT ${now}
    );
    CREATE OR REPLACE VIEW citizen_users AS
      SELECT id, name, email, cpf, phone, state, city, latitude, longitude, location_consent, created_at
      FROM users WHERE role = 'citizen';
    CREATE OR REPLACE VIEW institutional_users AS
      SELECT id, name, email, institution, functional_id, institutional_type, state, city, created_at
      FROM users WHERE role = 'institutional';
  `);
  for (const table of recordTables) {
    await sql.unsafe(`CREATE TABLE IF NOT EXISTS ${table} (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      region TEXT NOT NULL DEFAULT 'Salvador',
      event_date TEXT NOT NULL,
      event_time TEXT NOT NULL DEFAULT '',
      source TEXT NOT NULL DEFAULT 'Institucional',
      status TEXT NOT NULL DEFAULT 'Pendente',
      confidence INTEGER NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
      details TEXT NOT NULL DEFAULT '',
      created_by TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT ${now},
      updated_at TEXT NOT NULL DEFAULT ${now}
    )`);
  }
  await sql.unsafe(`
    ALTER TABLE occurrences
      ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'Normal',
      ADD COLUMN IF NOT EXISTS evidence_name TEXT,
      ADD COLUMN IF NOT EXISTS evidence_type TEXT,
      ADD COLUMN IF NOT EXISTS evidence_data TEXT,
      ADD COLUMN IF NOT EXISTS contact_authorized BOOLEAN NOT NULL DEFAULT false,
      ADD COLUMN IF NOT EXISTS anonymous BOOLEAN NOT NULL DEFAULT false,
      ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION,
      ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION,
      ADD COLUMN IF NOT EXISTS city TEXT,
      ADD COLUMN IF NOT EXISTS state TEXT;
    ALTER TABLE patrols
      ADD COLUMN IF NOT EXISTS result TEXT,
      ADD COLUMN IF NOT EXISTS recommendation_followed BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE contests
      ADD COLUMN IF NOT EXISTS evidence_name TEXT,
      ADD COLUMN IF NOT EXISTS evidence_type TEXT,
      ADD COLUMN IF NOT EXISTS evidence_data TEXT;
  `);
}

export async function getDb() {
  if (!client) {
    client = postgres(connectionString(), { ssl: "require", prepare: false, max: 5, idle_timeout: 20, onnotice: () => {} });
  }
  if (!ready) ready = migrate(client).catch((error) => { ready = undefined; throw error; });
  await ready;
  return client;
}

export function isUniqueViolation(error: unknown) {
  return typeof error === "object" && error !== null && (error as { code?: string }).code === "23505";
}
