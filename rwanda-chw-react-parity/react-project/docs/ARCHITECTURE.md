# Architecture

Browser → React/Vite → Express REST API → MySQL.

Authentication uses JWT bearer tokens. Passwords are bcrypt hashes. API endpoints use parameterized MySQL queries, allow-listed resource/table mappings, role checks, rate limiting, Helmet and CORS. Important mutations are recorded in `audit_logs`.
