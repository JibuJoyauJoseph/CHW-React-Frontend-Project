# Node.js + Express API

This is the production-style API for the Rwanda CHW-RHIS React application.

## Run

```powershell
npm install
copy .env.example .env
npm run seed
npm run dev
```

API: http://localhost:5000/api

The API implements authentication, JWT access tokens, CSRF protection, role permissions, scope filtering, CRUD, report workflow, imports, notifications, preferences and audit logging against MySQL.
