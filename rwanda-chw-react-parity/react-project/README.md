# Rwanda CHW-RHIS — React + Node.js + MySQL

This version keeps the React interface while reproducing the behavior of the PHP reference application through a Node.js/Express API and MySQL database.

## Architecture

React + Vite -> Node.js + Express -> MySQL

PHP is not required to run this version. The original PHP project is retained separately only as a behavioral/reference source.

## Start on Windows/XAMPP

1. Start MySQL from XAMPP.
2. Import `database/schema.sql` into MySQL.
3. Open `server/.env.example`, save a copy as `server/.env`, and set your MySQL credentials.
4. In PowerShell:

```powershell
cd server
npm install
npm run seed
npm run dev
```

5. In another PowerShell window:

```powershell
cd rwanda-chw-react
npm install
npm run dev
```

6. Open http://localhost:5173

Default demo password: `Demo@123`

Demo accounts are shown on the login screen.

## API

Node API: http://localhost:5000/api

React uses `VITE_API_URL=/api` with the Vite development proxy. For a different API host, set `VITE_API_URL` in the React `.env` file.
