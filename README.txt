Rust Bug Tracking System

This project is a web-based bug tracking system built using the Actix-web framework and SQLite as the backend database. It includes user authentication, bug and developer management, and project tracking. The system features both JSON-based APIs and web-based form submissions.

Core Features (Basic Requirements)

1. Bug Report Creation
   - `POST /bugs/new`: Creates a new bug report.
   - Accepts JSON body with `title`, `description`, `reported_by`, and `severity`.
   - Generates a UUID for each bug and stores the entry in SQLite.
   - Returns the full bug record with assigned `bug_id`.
   - Includes error handling for database issues.

2. Project List State Management
   - Uses a shared `Mutex<Vec<String>>` for in-memory project list.
   - `GET /projects`: Returns all projects as JSON.
   - `POST /projects`: Adds a new project (admin-only, protected by `Authorization` middleware).

3. User Login with Password Hashing
   - `POST /login`: Accepts `username` and `password` in JSON.
   - Hashes password using `SHA256(SALT + password)` with a static salt (`"bugtrack"`).
   - Compares against stored hash (e.g., "admin" user with password "password123").
   - Returns `{"status": "success", "token": "...fake_token..."}` on success, or `{"status": "failure"}` on failure.

4. Bug Assignment with HTML Form (Tera)
   - `GET /bugs/assign`: Displays a Tera-rendered HTML form for assigning bugs.
   - `POST /bugs/assign`: Updates `developer_id` in the database for a given bug.
   - Returns confirmation page or error message if IDs are invalid.

5. Full CRUD for Bug Reports
   - `POST /bugs/new`: Create a bug (see above).
   - `GET /bugs`: List all bug reports as JSON.
   - `GET /bugs/{id}`: Retrieve a specific bug by `bug_id`.
   - `PATCH /bugs/{id}`: Update fields like `title`, `description`, `severity`, `developer_id`.
   - `DELETE /bugs/{id}`: Delete a bug by ID. Returns confirmation or 404 if not found.


Extra Features

- HTML Login Form:
   - `GET /page/login`: HTML login page rendered with Tera.
   - `POST /page/login`: Processes login via form. If valid, redirects to bug assignment page.
   - Adds a user-friendly interface for browser-based users.

- Developer Management:
   - `POST /developers/new`: Add developers via API (with name and access level).

- Middleware Authorization:
   - Middleware-based check to restrict access to protected endpoints like `POST /projects`.

- Password Handling:
   - Modular SHA256 password hashing function to improve security.
   - Easy to replace or upgrade to more secure hashing (e.g., bcrypt, argon2) in the future.

- Templating Engine (Tera):
   - Clean integration of Tera templates for form rendering and response pages (e.g., `assign.html`, `login.html`).


Dependencies

- actix-web
- sqlx (SQLite)
- uuid
- bcrypt
- sha2
- once_cell
- tera
- chrono


How to Run

1. Ensure Rust and SQLite are installed.
2. Create and migrate the SQLite database with tables for `bugs`, `projects`, and `developers`.
3. Start the server with `cargo run`.
4. Access the application via your browser or Postman:
   - Web UI: `http://localhost:<PORT>/page/login`
   - API: Use endpoints under `/bugs`, `/projects`, and `/login`

