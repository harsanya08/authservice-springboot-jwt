# 🛡️ JWTGuard AI

## AI-Powered API Security Assistant

JWTGuard AI is an AI-assisted API security system built on top of a Spring Boot JWT authentication application.

It analyzes API security events using contextual information such as:

- IP address
- API endpoint
- HTTP method
- Failed authentication attempts
- Requests per minute
- User role

The system classifies the security risk as:

- 🟢 LOW
- 🟡 MEDIUM
- 🔴 HIGH

and recommends:

- ALLOW
- REVIEW
- BLOCK

---

## 💡 Problem

Traditional JWT authentication verifies whether a user is authenticated and authorized, but it does not provide contextual analysis of suspicious API activity.

For example, an authenticated user may still:

- Repeatedly fail authentication
- Send an unusually high number of requests
- Attempt to access administrative endpoints without the required role

JWTGuard AI adds an intelligent security-analysis layer to identify these suspicious patterns.

---

## 🚀 Solution

JWTGuard AI combines:

**JWT Authentication + AI Security Analysis + Deterministic Security Policies**

The AI layer analyzes security events and provides a risk assessment and recommended action.

A deterministic fallback layer ensures that the application can still make a security decision when the AI service is unavailable or rate-limited.

---

## 🏗️ Architecture

```text
                 ┌─────────────────────┐
                 │     Web Dashboard   │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │    Spring Boot API  │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │  Security Analysis  │
                 │      Service        │
                 └──────────┬──────────┘
                            │
                   ┌────────┴─────────┐
                   ▼                  ▼
          ┌────────────────┐   ┌──────────────────┐
          │   Gemini AI    │   │ Deterministic    │
          │    Analysis    │   │ Security Fallback│
          └───────┬────────┘   └────────┬─────────┘
                  │                     │
                  └──────────┬──────────┘
                             ▼
                  ┌─────────────────────┐
                  │ Risk + Recommendation│
                  │                     │
                  │ LOW    → ALLOW      │
                  │ MEDIUM → REVIEW     │
                  │ HIGH   → BLOCK      │
                  └─────────────────────┘