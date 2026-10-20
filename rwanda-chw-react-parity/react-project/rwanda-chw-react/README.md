# Rwanda CHW-RHIS React frontend

This React application is the frontend implementation of the PHP version in `rwanda-chw-php`.
It uses the same PHP API, Node.js API authentication, CSRF token, MySQL database, role permissions,
scoped records, CRUD endpoints, report workflow, import endpoint, notifications, and user preferences.

## Run with XAMPP

1. Put the PHP application in Apache's `htdocs` directory, for example:
   `C:\xampp\htdocs\rwanda-chw-php`
2. Start Apache and MySQL.
3. Import/use the same `rwanda_chw_reporting` database used by the PHP version.
4. Confirm `.env` in the PHP project contains the correct MySQL settings.
5. In this React folder run:

   `npm install`
   `npm run dev`

6. Open `http://localhost:5173`.

The Vite proxy sends `/api/*` to `http://localhost/rwanda-chw-php/api/*` by default.
If your PHP folder has another URL, change `VITE_PHP_TARGET` in `.env`.

## Production

Run `npm run build` and serve the generated `dist` from a web server configured to route `/api/*`
to the PHP application's `/api/*` endpoint. The browser must remain on the same site as the PHP
session cookie, or the PHP API must be configured with appropriate CORS and cookie settings.

The React UI intentionally does not use the old Node/JWT demo API. The PHP application is the
reference backend so both versions operate on the same MySQL data and security rules.
