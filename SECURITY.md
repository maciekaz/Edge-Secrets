# Security Policy

## Supported Versions

Edge Secrets is a rolling-release application designed to be deployed directly from the `main` branch to Cloudflare Workers. 

| Version | Supported          |
| ------- | ------------------ |
| Latest (`main` branch) | ✅ |
| Older commits | ❌ |

Strongly recommend keeping your deployment up to date by periodically pulling the latest changes and running `npx wrangler deploy`.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you believe you have found a security vulnerability in Edge Secrets (especially regarding the Web Crypto E2E implementation, Turnstile bypass, or CF Access logic), please report it securely using GitHub's Private Vulnerability Reporting feature.

### How to report:
1. Go to the **Security** tab of this repository.
2. Click on **Advisories** in the left sidebar.
3. Click the **Report a vulnerability** button.
4. Provide details about the exploit, including steps to reproduce.

### What to expect:
* I will review and acknowledge your report within 14 days.
* We will collaborate in the private advisory thread to confirm the vulnerability and develop a patch.
* Once patched, you will be publicly credited in the release notes and the README (unless you prefer to remain anonymous).

*Note: This is a free, open-source project. While there is no paid bug bounty program, finding a bypass in the E2E encryption or Edge architecture will earn you my eternal respect and public credit.*
