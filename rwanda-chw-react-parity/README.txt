RWANDA CHW-RHIS — REACT/PHP PARITY PACKAGE

The React frontend in react-project/rwanda-chw-react is configured to use the PHP application in php-reference as its backend/reference implementation.

SETUP
1. Copy php-reference to C:\xampp\htdocs\rwanda-chw-php (or change VITE_PHP_TARGET in react-project/rwanda-chw-react/.env).
2. Configure php-reference/.env for your MySQL database.
3. Start Apache and MySQL in XAMPP.
4. Ensure the PHP database schema and the user_preferences migration are installed.
5. Open a terminal in react-project/rwanda-chw-react.
6. Run: npm install
7. Run: npm run dev
8. Open: http://localhost:5173

PARITY
React uses the PHP session authentication and CSRF token, the PHP API, the same MySQL database, role permissions, scope filtering, CRUD rules, report workflow, JSON import, notifications, and persisted preferences. The old Node/JWT API is not used by the React frontend.

IMPORTANT
The supplied PHP reference application is the source of truth. If you change its database credentials or URL, update the React .env accordingly.
