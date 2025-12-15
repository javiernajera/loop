# GitHub Actions CI/CD Workflows

This directory contains automated workflows for continuous integration, deployment, and repository management.

## Workflows Overview

### 🔄 CI Workflow (`ci.yml`)
**Trigger:** Push to `main`/`develop`, Pull Requests

Runs on every push and pull request to ensure code quality:
- **Lint:** Checks code style and quality
- **Test:** Runs tests on Node.js 18 and 20
- **Build:** Creates production build artifacts
- **Security:** Performs npm audit and Trivy vulnerability scanning

### 🚀 CD Workflow (`cd.yml`)
**Trigger:** Push to `main`, Release published

Handles automated deployments:
- **Staging:** Automatically deploys to staging on `main` branch pushes
- **Production:** Deploys to production when a release is published
- Includes smoke tests after each deployment

### 🔍 Code Quality Workflow (`code-quality.yml`)
**Trigger:** Push to `main`/`develop`, Pull Requests, Weekly schedule

Performs comprehensive code analysis:
- **CodeQL:** Security vulnerability scanning
- **SonarCloud:** Code quality and coverage analysis
- **Code Coverage:** Tracks test coverage trends

### 📝 PR Management Workflow (`pr-management.yml`)
**Trigger:** Pull Request events

Automates PR management:
- Auto-labels PRs based on changed files
- Labels PRs by size (XS, S, M, L, XL)
- Validates PR titles follow semantic conventions
- Detects merge conflicts

### 📦 Release Workflow (`release.yml`)
**Trigger:** Version tags (v*.*.*)

Automates release process:
- Creates GitHub releases with auto-generated changelogs
- Publishes to NPM registry
- Builds and pushes Docker images to GitHub Container Registry

### ⏰ Scheduled Tasks Workflow (`scheduled.yml`)
**Trigger:** Daily at 2 AM UTC, Manual

Runs maintenance tasks:
- Security audits of dependencies
- Link checking in documentation
- Cleanup of old artifacts and workflow runs

### 🧹 Stale Issues/PRs Workflow (`stale.yml`)
**Trigger:** Daily at midnight

Manages stale content:
- Marks issues/PRs inactive for 60 days as stale
- Auto-closes stale items after 7 days of no activity
- Exempts pinned, security, and bug issues

## Configuration Files

### `dependabot.yml`
Configures automated dependency updates:
- Weekly updates for npm packages
- Weekly updates for GitHub Actions
- Auto-assigns PRs and adds labels

### `labeler.yml`
Defines rules for auto-labeling PRs based on file changes:
- Documentation, dependencies, CI/CD, tests
- Frontend, backend, database changes
- Configuration files

### `changelog-config.json`
Configures automatic changelog generation for releases:
- Categorizes changes by type (features, fixes, etc.)
- Formats release notes

### `markdown-link-check-config.json`
Configures link checking in documentation:
- Ignores localhost URLs
- Retry configuration for flaky links

## Required Secrets

Configure these secrets in your repository settings:

### For CI/CD
- `STAGING_DEPLOY_TOKEN` - Token for staging deployments
- `PRODUCTION_DEPLOY_TOKEN` - Token for production deployments

### For Code Quality
- `CODECOV_TOKEN` - Codecov integration token
- `SONAR_TOKEN` - SonarCloud authentication token

### For Release
- `NPM_TOKEN` - NPM registry authentication token
- `GITHUB_TOKEN` - Automatically provided by GitHub

## Environment Configuration

Set up the following environments in your repository:

1. **staging**
   - URL: https://staging.loop.example.com
   - Protection rules as needed

2. **production**
   - URL: https://loop.example.com
   - Enable required approvals for deployments

## Usage

### Running Workflows Manually

Some workflows support manual triggering via `workflow_dispatch`:
1. Go to Actions tab
2. Select the workflow
3. Click "Run workflow"

### Creating a Release

1. Create and push a version tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
2. The release workflow will automatically:
   - Build the application
   - Create a GitHub release
   - Publish to NPM
   - Build and push Docker image

### Customizing Workflows

To adapt these workflows to your project:

1. Update Node.js commands in `ci.yml` and `cd.yml` to match your `package.json` scripts
2. Modify deployment commands in `cd.yml` for your infrastructure
3. Adjust Dependabot schedule and reviewers in `dependabot.yml`
4. Update environment URLs in `cd.yml`

## Best Practices

- **Commit Messages:** Use conventional commits (feat, fix, docs, etc.) for better changelogs
- **PR Titles:** Follow semantic format for automatic categorization
- **Testing:** Ensure tests pass locally before pushing
- **Secrets:** Never commit secrets to the repository
- **Dependencies:** Review Dependabot PRs promptly

## Troubleshooting

### Workflow Failures
- Check the Actions tab for detailed logs
- Ensure all required secrets are configured
- Verify Node.js version compatibility

### Deployment Issues
- Confirm environment secrets are set
- Check deployment target availability
- Review smoke test results

### Code Quality Alerts
- Address CodeQL security findings
- Review SonarCloud quality gates
- Improve test coverage for failing files

## Support

For issues or questions about these workflows, please:
1. Check the GitHub Actions documentation
2. Review workflow logs for specific errors
3. Open an issue in this repository
