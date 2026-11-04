# AuthGuard

AuthGuard is a small authentication system I built to understand and implement the security controls that should exist behind a normal login system.

Instead of only focusing on the login page, I wanted to look at what happens after a user enters their credentials, password hashing.


I did this as a semester project for cryptography project. 

## What it includes

* User registration and login
* Argon2id password hashing
* Password strength checking using `zxcvbn`
* Password history
* Brute-force protection and account lockout
* Per-IP login throttling
* TOTP-based MFA
* Backup codes for MFA
* Server-side sessions
* Session expiration and session revocation
* CSRF protection
* Security/activity logs
* Security headers
* SQLite for local development
* PostgreSQL support through Docker
## Project structure
```text
authguard/
│
├── app/
│   ├── main.py
│   ├── config.py
│   ├── db.py
│   ├── models.py
│   ├── init_db.py
│   │
│   ├── routes/
│   │   ├── auth.py
│   │   ├── account.py
│   │   └── api.py
│   │
│   ├── security/
│   │   ├── passwords.py
│   │   ├── policy.py
│   │   ├── sessions.py
│   │   ├── csrf.py
│   │   ├── throttle.py
│   │   ├── totp.py
│   │   └── events.py
│   │
│   ├── templates/
│   └── static/
│
├── tests/
├── docs/
├── requirements.txt
├── requirements-dev.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── pytest.ini



---

# Running it locally

## 1. Clone the project

```bash
git clone <your-repository-url>
cd authguard
```

## 2. Create a virtual environment

I recommend using Python 3.11 or 3.12 for this project.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
```
Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the activation script, you can use:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

without activating the environment.

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3. Install the dependencies

Use Python to run pip instead of calling `pip` directly:

```bash
python -m pip install -r requirements-dev.txt
```

For the normal application dependencies only:

```bash
python -m pip install -r requirements.txt
```

Using `python -m pip` also makes sure the packages are installed into the Python environment you're actually using.

---

## 4. Create the environment file

Copy the example environment file:

### Windows

```powershell
Copy-Item .env.example .env
```

### Linux / macOS

```bash
cp .env.example .env
```

For local development, the default `.env.example` is already set up to use SQLite.

You should have:

```env
AUTHGUARD_ENV=dev
DATABASE_URL=sqlite:///./authguard.db
COOKIE_SECURE=false
```

The development environment can generate a temporary `SECRET_KEY` automatically.

For a more permanent setup, generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Then put the generated value into `.env`:

```env
SECRET_KEY=your-generated-secret-key
```

Do not commit the `.env` file.

---

## 5. Initialize the database

Run:

```bash
python -m app.init_db
```

If everything is set up correctly, you should see:

```text
tables ready
```

For local development this creates the SQLite database:

```text
authguard.db
```

---

## 6. Start the application

Run:

```bash
python -m uvicorn app.main:app --reload
```

The application should be available at:

```text
http://127.0.0.1:8000
```

Open that address in your browser.

---

# Windows troubleshooting

If you get an error saying that `pip.exe` is blocked by Windows Application Control, don't use:

```powershell
pip install -r requirements-dev.txt
```

Use:

```powershell
python -m pip install -r requirements-dev.txt
```

If `uvicorn` is not recognized, don't run:

```powershell
uvicorn app.main:app --reload
```

Use:

```powershell
python -m uvicorn app.main:app --reload
```

This is also useful when multiple Python installations are present on Windows.

To check which Python is being used:

```powershell
python --version
where.exe python
```

To check pip:

```powershell
python -m pip --version
```

---

# Running with Docker

Docker runs the application with PostgreSQL instead of SQLite.

First create the environment file:

```bash
cp .env.example .env
```

Generate a secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put it into `.env`:

```env
SECRET_KEY=your-generated-secret-key
```

Then start the containers:

```bash
docker compose up --build
```

The application will be available at:

```text
http://localhost:8000
```

The Docker setup contains:

* PostgreSQL 16
* AuthGuard application
* Persistent PostgreSQL volume
* Database health check
* Automatic database initialization

To stop it:

```bash
docker compose down
```

To stop it and remove the database volume:

```bash
docker compose down -v
```

---

# Running the tests

Install the development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Then run:

```bash
pytest
```

The tests cover things such as:

* Password hashing
* Password policy
* Registration
* Login
* Wrong password handling
* Account lockout
* Lockout expiration
* CSRF protection
* Session expiration
* Session revocation
* Password changes
* MFA setup
* TOTP verification
* Backup codes
* MFA replay protection

---

# Authentication flow

The login process is roughly:

```text
User
  |
  v
Email + Password
  |
  v
IP rate limit
  |
  v
Account lockout check
  |
  v
Argon2id password verification
  |
  +---- Invalid ----> Record failure
  |
  v
MFA enabled?
  |
  +---- No ----> Create session
  |
  +---- Yes ---> TOTP / Backup Code
                    |
                    v
                Create session
                    |
                    v
                 Dashboard
```

For unknown email addresses, the application also performs password verification against a dummy hash. This helps avoid making the difference between an existing and non-existing account obvious from response timing.

---

# Security controls

### Passwords

Passwords are never stored directly.

AuthGuard uses Argon2id with the following default parameters:

```text
Memory:       64 MiB
Iterations:   3
Parallelism:  4
```

There are also password policy checks for:

* Minimum password length
* Common passwords
* Personal information
* Password strength
* Password reuse

The last five passwords are tracked to prevent immediate reuse.

### Brute-force protection

After five failed attempts within the configured window, the account is temporarily locked.

There is also a per-IP limit to make large-scale credential stuffing harder.

### MFA

AuthGuard supports TOTP-based MFA.

It can be used with apps such as:

* Google Authenticator
* Microsoft Authenticator
* Aegis

Backup codes are also generated so the account can still be accessed if the authenticator device is unavailable.

### Sessions

Sessions are stored server-side rather than using JWTs.

The browser receives a random session token in a protected cookie.

Sessions have:

* Idle timeout
* Absolute timeout
* Server-side revocation
* Secure cookie flags
* `HttpOnly`
* `SameSite=Strict`

Changing a password or logging out invalidates the relevant sessions.

### CSRF protection

State-changing requests use CSRF protection.

The application also checks request headers such as:

```text
Sec-Fetch-Site
Origin
```

to make cross-site requests harder to abuse.

### Security headers

The application adds security-related headers including:

* Content Security Policy
* HSTS
* X-Content-Type-Options
* Cache-Control
* Frame protection

---

# Configuration

Most settings can be changed through `.env`.

Some of the main options are:

| Variable                 | Default | Purpose                        |
| ------------------------ | ------: | ------------------------------ |
| `AUTHGUARD_ENV`          |  `prod` | Application environment        |
| `SECRET_KEY`             |       — | Main application secret        |
| `DATABASE_URL`           |  SQLite | Database connection            |
| `COOKIE_SECURE`          |  `true` | Secure session cookies         |
| `SESSION_IDLE_MINUTES`   |    `30` | Idle session timeout           |
| `SESSION_ABSOLUTE_HOURS` |    `12` | Maximum session lifetime       |
| `MAX_FAILED_ATTEMPTS`    |     `5` | Failed attempts before lockout |
| `LOCKOUT_MINUTES`        |    `15` | Lockout duration               |
| `MIN_PASSWORD_LENGTH`    |    `12` | Minimum password length        |
| `PASSWORD_HISTORY`       |     `5` | Number of previous passwords   |
| `LOGIN_IP_LIMIT`         |    `30` | Login attempts allowed per IP  |
| `IP_WINDOW_MINUTES`      |    `10` | IP throttling window           |

The complete list is available in `.env.example`.

---

# Database

For local development, AuthGuard uses SQLite:

```env
DATABASE_URL=sqlite:///./authguard.db
```

For PostgreSQL:

```env
DATABASE_URL=postgresql+psycopg://authguard:password@localhost:5432/authguard
```

The Docker setup already provides PostgreSQL, so normally no manual PostgreSQL configuration is needed when using Docker.

---

# Screenshots

### Registration

![Registration](docs/screenshots/register.png)

### Login

![Login](docs/screenshots/login.png)

### MFA Setup

![MFA Setup](docs/screenshots/mfa-setup.png)

### Dashboard

![Dashboard](docs/screenshots/dashboard.png)

### Security Settings

![Security](docs/screenshots/security.png)

### Backup Codes

![Backup Codes](docs/screenshots/backup-codes.png)

---

# Current limitations

There are still a few things I would improve if this was taken further:

* No database migrations yet; tables are currently created using `create_all`
* No email verification
* No password reset flow
* No Have I Been Pwned password check
* No backup-code regeneration
* The password-strength endpoint has a per-process rate limit
* PostgreSQL/Docker setup is included, but most testing has been done with SQLite
* WebAuthn/passkeys are not implemented yet

---

# Why I built this

The main goal of this project was to get a better understanding of authentication from a security point of view.

A login form by itself is pretty simple. The interesting part is everything around it — how passwords are stored, how failed attempts are handled, how sessions are created and revoked, how MFA is implemented, and how common web attacks are handled.

I also wanted the security decisions to be visible in the code instead of treating authentication as a black box.

---

## Tech stack

* Python
* FastAPI
* SQLAlchemy
* SQLite / PostgreSQL
* Argon2id
* TOTP
* Jinja2
* Pytest
* Docker

---

Built by **sthapit27ps**
