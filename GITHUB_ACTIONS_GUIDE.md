# GitHub Actions Quick Start Guide

This repository includes a comprehensive CI/CD setup using GitHub Actions. Here's what you need to know:

## 🚀 What's Automated

- ✅ **CI/CD**: Automated testing, linting, building, and deployment
- 🔒 **Security**: CodeQL analysis, dependency audits, vulnerability scanning
- 📦 **Releases**: Automated GitHub releases, NPM publishing, Docker images
- 🏷️ **PR Management**: Auto-labeling, size tracking, semantic validation
- 🧹 **Maintenance**: Dependency updates, stale issue management, cleanup tasks

## 📋 Prerequisites

To use these workflows, you'll need to configure:

### Required Secrets
Add these in Settings → Secrets and variables → Actions:

1. **CODECOV_TOKEN** - For code coverage reporting
2. **SONAR_TOKEN** - For SonarCloud analysis (optional)
3. **STAGING_DEPLOY_TOKEN** - For staging deployments
4. **PRODUCTION_DEPLOY_TOKEN** - For production deployments
5. **NPM_TOKEN** - For NPM publishing (if releasing packages)

### Required Environments
Create these in Settings → Environments:

1. **staging** 
   - URL: Update in `.github/workflows/cd.yml`
   - Add protection rules as needed

2. **production**
   - URL: Update in `.github/workflows/cd.yml`
   - Enable required reviewers for safety

## 🔧 Adapting to Your Project

Once you have actual code, update these files:

1. **package.json** - Add these scripts:
   ```json
   {
     "scripts": {
       "lint": "your-linter-command",
       "test": "your-test-command",
       "test:coverage": "your-coverage-command",
       "build": "your-build-command"
     }
   }
   ```

2. **.github/workflows/cd.yml** - Update deployment commands:
   - Replace placeholder deployment commands with your actual deployment logic
   - Update environment URLs

3. **.github/labeler.yml** - Adjust file patterns to match your project structure

## 📚 Learn More

For detailed documentation, see [.github/README.md](.github/README.md)

## 🎯 Next Steps

1. ✅ Configure required secrets
2. ✅ Set up environments
3. ✅ Add your application code
4. ✅ Update package.json scripts
5. ✅ Customize deployment commands
6. ✅ Test workflows by creating a PR

## 💡 Tips

- Use conventional commit format: `feat:`, `fix:`, `docs:`, etc.
- PRs are automatically labeled based on changed files
- Security scans run on every push
- Deployments to staging are automatic on `main` branch
- Production deployments happen on release tags (`v1.0.0`)

---

For questions or issues, refer to the workflow files in `.github/workflows/` or consult the documentation.
