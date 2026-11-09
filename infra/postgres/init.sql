-- Enable pgvector extension for high-performance vector search
CREATE EXTENSION IF NOT EXISTS vector;

-- Enable UUID extension for robust distributed IDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_trgm for full-text / trigram fuzzy matching
CREATE EXTENSION IF NOT EXISTS pg_trgm;

