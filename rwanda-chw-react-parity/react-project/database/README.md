# MySQL database
1. Start MySQL in XAMPP.
2. Open phpMyAdmin or MySQL CLI.
3. Import `schema.sql`.
4. From `server/`, copy `.env.example` to `.env` and set your MySQL password.
5. Run `npm install`.
6. Run `npm run seed` to load the fictional CHW demonstration data.

The React application does not require PHP. Runtime architecture is:

React/Vite -> Node.js/Express API -> MySQL
