# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Email:** avhidotsol@gmail.com

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

This tool performs static analysis only. It does not execute, compile, or deploy any Solana programs. It reads source files and parses them using the `syn` crate.

The GitHub token provided to this action is used solely for:

- Posting comments on pull requests
- Creating check runs

It does not modify repository contents, branches, or settings.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
