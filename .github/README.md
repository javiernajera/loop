# Loop App Repository

This repository contains the source code and infrastructure for the **Loop** application.  The goal of Loop is to onboard new users, send them a personalized survey link, and capture their feedback.  The project is broken into three major parts:

1. **Backend Lambdas** – AWS Lambda functions that validate a new user signup, store the user in DynamoDB, send them a survey link via email, and accept survey responses.
2. **Shared Code** – Reusable data models and DynamoDB repository helpers used by the lambda functions.
3. **Static Front‑end** – A simple HTML/JavaScript survey page that users can load from a static website (S3/CloudFront).

## Directory Structure

```
loop-app/
├── README.md                 # This file
├── requirements.txt          # Python dependencies for the lambda functions
├── src/                      # Reusable modules shared between lambdas
│   ├── models.py             # Data classes for users and surveys
│   ├── ddb_repo.py           # DynamoDB repository for user signups
│   └── survey_repo.py        # DynamoDB repository for survey responses
├── lambda/                   # AWS Lambda handlers
│   ├── signup/
│   │   └── lambda_function.py  # Handler for user signup
│   └── survey_submit/
│       └── lambda_function.py  # Handler for survey submission
└── static/
    └── survey.html           # Self‑contained survey page
```

### Backend Lambdas

- **Signup Lambda** (`lambda/signup/lambda_function.py`):
  - Accepts a `POST` request containing a user’s email and optional source.
  - Validates the email, generates a random survey token, stores a new user record in DynamoDB, and sends the survey link via AWS SES.
  - Uses the shared `UserSignup` data class and `UserRepo` for persistence.

- **Survey Submit Lambda** (`lambda/survey_submit/lambda_function.py`):
  - Accepts a `POST` request containing a survey token and the user’s answers.
  - Verifies that the token exists by looking up the hashed value on a DynamoDB global secondary index.
  - Writes a survey response to the `LoopSurveys` table using the `SurveyRepo` data class.

Both lambdas expect the following environment variables:

- `USERS_TABLE`: Name of the DynamoDB table storing user signups.
- `SURVEYS_TABLE`: Name of the DynamoDB table storing survey responses (used only by the submit lambda).
- `SURVEY_BASE_URL`: Base URL for generating survey links (used only by the signup lambda).
- `SES_FROM_EMAIL`: Verified sender email address for AWS SES (used only by the signup lambda).
- `ALLOWED_ORIGIN`: CORS header for front‑end requests.

### Shared Code

The `src` directory contains plain Python modules that define data models and simple repositories over DynamoDB.  Using these modules in both lambda functions avoids code duplication and allows consistent data shapes:

- `UserSignup` and `SurveyResponse` are defined as data classes in `models.py`.  They expose convenience methods for building DynamoDB items and computing primary keys.
- `ddb_repo.py` encapsulates queries and conditional writes against the users table.  It also demonstrates how to look up users by their hashed survey tokens using a global secondary index (GSI).
- `survey_repo.py` provides a simple wrapper to insert survey responses into DynamoDB.

### Static Survey Page

The `static/survey.html` file is a self‑contained page that can be hosted on Amazon S3 with static web hosting enabled (or behind a CloudFront distribution).  It extracts the token from the URL query string, collects survey responses from the user, and submits them to the survey submit lambda via a `fetch` request.

Before deploying the front‑end, update the constant `SURVEY_SUBMIT_ENDPOINT` in the HTML file to point to the public URL for your survey submit lambda (e.g. a Function URL or API Gateway endpoint).

### Getting Started

To develop locally:

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Run unit tests or the lambda handlers locally (optional).  The code relies on AWS services, so you may wish to use the [aws-cli](https://aws.amazon.com/cli/) or [localstack](https://github.com/localstack/localstack) for local testing.
4. Deploy the lambdas using your infrastructure as code of choice (e.g. AWS SAM, CDK, or Terraform).  Ensure that the DynamoDB tables and global secondary index are created with the keys described in the docs.

### Notes

- The repository includes no AWS credentials or deployment scripts.  Provision infrastructure using your preferred tooling.
- Use a `.gitignore` (not shown here) to exclude build artifacts, virtual environments, or credentials.
- For production workloads, you may wish to use KMS to encrypt tokens, implement retries on email sending, and refine input validation.  The provided code is intended as a starting point and does not include every best practice.
