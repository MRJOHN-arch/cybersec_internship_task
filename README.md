CyberShield V3: Advanced Security Portal

Internship Project: Weeks 4 & 5 Hardening & Exploitation

This repository contains a hardened Node.js application developed during the Cybersecurity Internship. The project demonstrates a transition from a vulnerable legacy system to a modern, secure architecture.

Current Security Status: Week 5 (Hardened)

Core Technologies

Backend: Node.js, Express.js

Database: SQLite3

Security Middleware: helmet, csurf, express-rate-limit, cors, cookie-parser

Testing Tools: SQLMap, Burp Suite, Nmap, Nikto

Implemented Security Features

Week 4: Advanced Threat Detection

Intrusion Detection: Configured Fail2Ban to monitor security.log and automatically ban IPs after 5 failed login attempts.

API Hardening: Implemented express-rate-limit to prevent brute-force attacks (10 attempts per 10 minutes).

CORS Configuration: Configured CORS to restrict access to authorized origins only.

Security Headers: Integrated Helmet.js to enforce HSTS (HTTPS enforcement).

Content Security Policy: Implemented a strict CSP to mitigate XSS and script injection.

Week 5: SQLi and CSRF Mitigation

SQL Injection Prevention: Identified vulnerabilities in legacy routes using SQLMap and migrated all database queries to Prepared Statements (Parameterized Queries) to eliminate SQLi risks.

CSRF Protection: Implemented csurf middleware with secure cookie storage.

Validation: Verified protection by intercepting and manipulating requests in Burp Suite to ensure unauthorized state-changing requests are blocked.

Ethical Hacking and Audit Results

1. Reconnaissance

Nmap Scan: Verified service availability on Port 3000.

Nikto Audit: Scanned for misconfigured headers and outdated server signatures.

2. SQLMap Exploitation (Task 2)

Vulnerability: The /api/login-vulnerable endpoint was found susceptible to UNION-based SQLi.

Result: Successfully extracted database schema in a controlled test environment.

Fix: Applied parameterized inputs to ensure user data is never treated as executable code.

3. Burp Suite CSRF Testing (Task 3)

Attack Simulation: Attempted POST requests without the required CSRF-Token header.

Defense Result: Server correctly responded with 403 Forbidden, validating the effectiveness of the mitigation.

Installation and Setup

Clone the repository:
git clone https://github.com/MRJOHN-arch/cybersec_internship_task
cd cybersec_internship_tasks

Install Dependencies:
npm install

Run the Server:
node app2.js

Monitor Security Logs:
tail -f security.log


