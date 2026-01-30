# Loop

Loop is a matchmaking and anonymous relay system that pairs artists weekly, creates private relay aliases, and introduces matches over email while keeping addresses private.

Live site: https://www.theloopletter.com

## High‑Level Architecture

1) **Signup & Survey**
- Users sign up and receive a survey link.
- Survey responses are stored and used to score compatibility.

2) **Matchmaking**
- Weekly matcher loads survey responses, scores pairs, avoids repeats, and writes match records.
- For each pair it creates a relay conversation with two aliases (one per user).

3) **Email Relay**
- Incoming email is routed via relay aliases to the matched user.
- Users only see relay aliases, not each other’s real email.

4) **Weekly Intro Sender**
- Sends intro emails to users for pairs that have not yet been emailed.
- Rate‑limits and retries to avoid Resend API throttling.

## Directory Structure

```
loop/
├── lambda/                 # AWS Lambda handlers (Python)
│   ├── loop_signup.py
│   ├── loop_survey.py
│   ├── loop_matchmaker.py
│   ├── loop_weekly_match.py
│   ├── loop_email_inbound.py
│   ├── loop_http_get_messages.py
│   ├── loop_http_presign_audio.py
│   ├── loop_ws_connect.py
│   ├── loop_ws_disconnect.py
│   └── loop_ws_send_message.py
├── src/                    # Shared DynamoDB helpers and models
│   ├── ddb_repo.py
│   ├── models.py
│   └── survey_repo.py
├── static/                 # Static web pages (survey + confirmations)
└── requirements.txt
```

## Core DynamoDB Tables

- **loop_users**: user profiles (pk=email, sk=PROFILE)
- **loop_surveys**: survey submissions
- **loop_matches**: weekly match pairs (two rows per pair)
- **loop_relays**: relay alias → destination mapping

## Key Lambdas

- **loop_signup.py**
  - Creates user record and sends survey link email via Resend.

- **loop_survey.py**
  - Receives survey submissions and stores responses.

- **loop_matchmaker.py**
  - Computes weekly matches and writes to loop_matches.
  - Creates relay aliases and writes to loop_relays.

- **loop_weekly_match.py**
  - Sends weekly intro emails only for matches where `intro_email_sent` is not true.
  - Uses Resend and rate‑limits to avoid 429s.

- **loop_email_inbound.py**
  - Processes inbound emails and relays messages through aliases.

## Email Relay Model

For a match (A, B), the matcher creates two aliases:

```
c_<token>a@theloopletter.com  -> routes to user A
c_<token>b@theloopletter.com  -> routes to user B
```

Each relay record stores:
- alias (PK)
- dest_email
- counterparty_alias
- allowed_senders
- conversation_id
- status, created_at, expires_at (TTL)

## Configuration (Env Vars)

Common:
- `MATCHES_TABLE`, `SURVEYS_TABLE`, `RELAYS_TABLE`

Matchmaker:
- `RELAY_TABLE` (default loop_relays)
- `RELAY_DOMAIN` (default theloopletter.com)
- `RELAY_TTL_DAYS`

Weekly Intro Sender:
- `RESEND_API_KEY` or `RESEND_SECRET_ID`
- `FROM_EMAIL` (default Loop <hello@theloopletter.com>)
- `RESEND_RATE_LIMIT_PER_SEC`, `RESEND_RETRY_MAX`, `RESEND_RETRY_BASE_DELAY`

## Running Locally

1) Create a virtual environment and install dependencies:
- `pip install -r requirements.txt`

2) Set AWS credentials and env vars for the target tables.

3) Invoke handlers directly (or via AWS CLI in your account).

## Notes

- This repo expects AWS infra (DynamoDB, Lambda, Resend). It does not provision resources.
- For production, keep Resend keys in Secrets Manager and give Lambdas access to `secretsmanager:GetSecretValue`.
- Use CloudWatch logs for operational debugging and delivery metrics.
