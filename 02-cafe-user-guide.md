# CAFE User Guide

This guide explains how to use the CAFE frontend to discover, assess, and manage cryptographic risks for Ethereum wallets and TLS endpoints.


## Document versionning

- v0.3.0
  - Date: Feb 26th, 2026
  - Comments: Documentation review and version/date update.
- v0.2.0
  - Date: Feb 1st, 2026
  - Comments: Navigation and routes updated for new interface (Discovery tabs, Platform); anonymous mode clarified (view-only without account, sign-in required to run scans).
- v0.1.0
  - Date: Jan 19th, 2026
  - Author: Oleg Lodygensky
  - Comments: initial version

## Table of Contents

1. [Getting Started](#getting-started)
2. [Authentication](#authentication)
3. [Dashboard](#dashboard)
4. [Wallet Scanning](#wallet-scanning)
5. [TLS Endpoint Scanning](#tls-endpoint-scanning)
6. [Viewing Scan Results](#viewing-scan-results)
7. [Security Page](#security-page)
8. [Settings and Plans](#settings-and-plans)
9. [Wallet Management](#wallet-management)
10. [Anonymous Mode](#anonymous-mode)

## Getting Started

### Accessing CAFE

CAFE is accessible via a web browser.

### First Visit

When you first visit CAFE, you can:

- **Browse anonymously** — View default endpoints and scan results without creating an account; to run new scans you must sign in or sign up. Anonymous data are temporary and not persisted long-term.
- **Create an account** — Sign up to run scans and save your results; your scans are stored in the backend so you can retrieve them when you reconnect.
- **Sign in** — If you already have an account

### Navigation

The main navigation menu provides access to:

- **Home** — Landing page with links to Discovery, Crypto Policy Management, and Remediation
- **Discovery** — Tabbed section with:
  - **Introduction** — Overview of Discovery (wallet and TLS exposure)
  - **Dashboard** — Overview of your scans and security statistics
  - **Wallet scan** — View and manage wallet security scans
  - **TLS scan** — View and manage TLS endpoint security scans
- **Crypto Policy Management** — Govern crypto policies for wallet assets (CPM)
- **Remediation** — Migration to post-quantum–resistant cryptography
- **Platform** — Sub-pages: **Status** (health, versions), **Security** (token inspection, refresh)
- **Networks (Chains)** — View supported blockchain networks
- **Settings** — Manage your profile and view plan information
- **Wallets** — Manage your saved wallets (requires authentication)

## Authentication

### Sign Up

To create a new account:

1. Click **Sign Up** in the navigation menu or on the sign-in page
2. Fill in the registration form:
   - **Email address** — Your email (used for login)
   - **Password** — Choose a strong password
   - **Confirm Password** — Re-enter your password
3. Complete the **Cloudflare Turnstile** verification (bot protection)
4. Click **Sign Up**

### Sign In

To sign in to your account:

1. Click **Sign In** in the navigation menu
2. Enter your **email address** and **password**
3. Complete the **Cloudflare Turnstile** verification
4. Click **Sign In**

After successful authentication, you'll receive a hybrid PQC JWT token (EdDSA + ML-DSA-65) that is automatically stored and used for subsequent API requests.

### Sign Out

To sign out:

1. Click on your profile/email in the navigation
2. Select **Sign Out**

Your session will be cleared and you'll be redirected to the sign-in page.

## Dashboard

The Discovery **Dashboard** (`/discovery/dashboard`) provides an overview of your security scanning activity and statistics.

### Overview Statistics

The dashboard displays four key metrics:

- **Total Scans** — Total number of scans performed (wallet + TLS)
- **High Risk** — Number of scans with high quantum risk
- **Medium Risk** — Number of scans with medium quantum risk
- **Safe** — Number of scans with low or no quantum risk

### Recent Scans

The dashboard shows your most recent scans, including:

- **Wallet scans** — Ethereum addresses scanned
- **TLS scans** — Endpoints scanned
- **Risk level** — Visual indicator (🔴 High, 🟡 Medium, 🟢 Safe)
- **Scan date** — When the scan was performed

### Quick Actions

From the dashboard, you can:

- **Start a new scan** — Click the "New Scan" button to scan a wallet or TLS endpoint
- **View scan details** — Click on any scan result to see detailed information
- **Filter scans** — Use the filters to find specific scans

## Wallet Scanning

CAFE can scan Ethereum wallets to assess their quantum vulnerability by checking if the public key has been exposed on-chain.

### Starting a Wallet Scan

1. Navigate to **Discovery → Dashboard** or **Discovery → Wallet scan**
2. Click the **"New Scan"** button (sign-in required if you are in anonymous mode)
3. In the scan modal:
   - Select **"Wallet Address"** as the scan type
   - Enter an Ethereum address (must start with `0x`)
   - Click **"Scan"**

### Understanding Wallet Scan Results

After scanning, you'll see one of three risk states:

#### 🔴 High Risk — Public Key Exposed

- **Meaning**: The wallet has executed at least one transaction
- **Risk**: The public key is permanently visible on the blockchain, making it vulnerable to future quantum attacks
- **Action**: Consider migrating to a quantum-safe Account Abstraction wallet (ERC-4337)

#### 🟡 Medium Risk — Public Key Not Exposed

- **Meaning**: The wallet has never executed a transaction
- **Risk**: While not immediately threatened, any future transaction would expose the public key
- **Action**: Consider creating a new quantum-safe wallet before first use

#### 🟢 Low Risk — CAFE Wallet Attached

- **Meaning**: The wallet is a CAFE-managed Account Abstraction wallet with PQC support
- **Risk**: Minimal — protected by post-quantum cryptography
- **Action**: Continue using this wallet for quantum-safe operations

### Multi-Chain Support

CAFE automatically scans wallets across multiple Ethereum-compatible chains:

- Ethereum Mainnet
- Arbitrum One
- Optimism
- Base
- Polygon
- And more...

The scan results show the risk status for each chain where the address has activity.

### Scan Details

Clicking on a scan result shows detailed information:

- **Address** — The Ethereum wallet address
- **Account Type** — EOA (Externally Owned Account) or AA (Account Abstraction)
- **Algorithm** — Cryptographic algorithm used (e.g., ECDSA-secp256k1)
- **NIST Security Level** — Quantum security level (1-5)
- **Key Exposed** — Whether the public key is visible on-chain
- **Risk Score** — Numerical risk assessment (0.0 to 1.0)
- **Networks** — Chains where the address has activity
- **CBOM** — Cryptographic Bill of Materials in CycloneDX format

## TLS Endpoint Scanning

CAFE can scan TLS endpoints (HTTPS URLs) to assess their post-quantum cryptography readiness.

### Starting a TLS Scan

1. Navigate to **Discovery → Dashboard** or **Discovery → TLS scan**
2. Click the **"New Scan"** button (sign-in required if you are in anonymous mode)
3. In the scan modal:
   - Select **"TLS Endpoint"** as the scan type
   - Enter an HTTPS URL (must start with `https://`)
   - Optionally specify a custom port (e.g., `https://example.com:8443`)
   - Click **"Scan"**

### Understanding TLS Scan Results

TLS scan results include:

#### Certificate Analysis

- **Subject** — Certificate subject (e.g., CN=example.com)
- **Issuer** — Certificate Authority
- **Signature Algorithm** — Algorithm used to sign the certificate
- **NIST Security Level** — Quantum security level of the certificate
- **PQC Ready** — Whether the certificate uses post-quantum cryptography

#### TLS Protocol Analysis

- **Protocol Version** — TLS 1.2 or TLS 1.3
- **Key Exchange** — Key exchange algorithm (e.g., X25519, ML-KEM)
- **Cipher Suites** — Supported encryption cipher suites
- **PFS (Perfect Forward Secrecy)** — Whether PFS is enabled
- **OCSP Stapling** — Whether OCSP stapling is enabled

#### Risk Assessment

- **Overall NIST Level** — Minimum security level across all components
- **Risk Score** — Comprehensive risk assessment (0.0 to 1.0)
- **PQC Mode** — Classical, hybrid, or pure PQC
- **Supported PQC** — List of post-quantum algorithms supported
- **Recommendations** — Actionable security recommendations

### Default Endpoints

CAFE automatically scans and maintains a list of default endpoints, including:

- Major Ethereum RPC providers (Ankr, Infura, Alchemy)
- Layer 2 networks (Arbitrum, Optimism, Base, Polygon zkEVM, etc.)
- PQC test servers (OpenQuantum Safe, Cloudflare)
- The frontend of the Webapp itself

These results are visible to all users and continuously updated.

## Viewing Scan Results

### Wallet Scans View

The Wallet Scans view is under **Discovery → Wallet scan** (`/discovery/wallet-scan`). It displays all your wallet scan results (and default or anonymous results when applicable).

#### Features

- **Search** — Search by wallet address
- **Filter by Risk** — Filter by High, Medium, Low, or Safe risk levels
- **Filter by Type** — Filter by EOA, AA, or Contract account types
- **Sort** — Sort by date, risk level, or address
- **Pagination** — Navigate through multiple pages of results

#### Scan List

Each scan result shows:

- **Address** — Ethereum wallet address (truncated for display)
- **Risk Badge** — Visual risk indicator
- **Account Type** — EOA, AA, or Contract
- **Algorithm** — Cryptographic algorithm
- **NIST Level** — Security level
- **Scan Date** — When the scan was performed

#### Viewing Details

Click on any scan result to view:

- Complete scan information
- Multi-chain status
- CBOM (Cryptographic Bill of Materials)
- Security recommendations
- Raw JSON data

### TLS Scans View

The TLS Scans view is under **Discovery → TLS scan** (`/discovery/tls-scan`). It displays all your TLS endpoint scan results (and default or anonymous results when applicable).

#### Features

- **Search** — Search by endpoint URL
- **Filter by Risk** — Filter by risk level
- **Filter by PQC Status** — Filter by PQC readiness
- **Default Endpoints** — View automatically scanned endpoints

#### Scan List

Each scan result shows:

- **URL** — The scanned endpoint
- **Host** — Domain name
- **Protocol** — TLS version
- **Risk Badge** — Visual risk indicator
- **NIST Level** — Security level
- **PQC Mode** — Classical, hybrid, or pure PQC
- **Scan Date** — When the scan was performed

#### Viewing Details

Click on any scan result to view:

- Complete certificate information
- TLS handshake details
- Cipher suite analysis
- NIST level breakdown (certificate, KEX, signature, cipher, HKDF, session)
- Risk score calculation
- Security recommendations
- CBOM (Cryptographic Bill of Materials)

## Security Page

The Security page is under **Platform → Security** (`/platform/security`). It provides information about your authentication tokens and security features.

### Security Features Overview

The page displays information about:

- **Anonymous Mode** — If you're not logged in, shows that scans are temporary
- **Cloudflare Turnstile** — Development mode warning (if using dev keys)
- **Post-Quantum Cryptography** — Information about hybrid PQC JWT tokens
- **Token-Based Authentication** — How JWT tokens are used

### JWT Token Information

The Security page shows detailed information about your authentication token:

#### Token Format

- **Type** — Hybrid PQC or Classic
- **Algorithms** — EdDSA and ML-DSA-65 (for hybrid tokens)
- **Number of Signatures** — 2 for hybrid tokens (one for each algorithm)

#### Token Details

Expandable sections show:

- **Signature Headers** — Headers for each signature algorithm
- **Payload** — Complete JWT claims (user ID, email, expiration, etc.)
- **Raw Token** — The complete token string

#### Token Refresh

To generate a new token:

1. Click the **"Refresh Token"** button
2. Enter your password in the modal
3. A new hybrid PQC token will be generated and stored automatically

**Note**: Token refresh requires your password for security. The new token will have a new expiration date.

## Settings and Plans

The Settings page (`/settings`) provides access to your account information and plan details. In anonymous mode it shows limited plan/usage information.

### User Profile

View and manage:

- **Email Address** — Your account email
- **Account Status** — Active, suspended, etc.

### Plan Information

View details about your current plan:

- **Plan Name** — Free, Pro, Enterprise, etc.
- **Plan Limits** — Scan limits, storage limits, etc.
- **Usage Statistics** — Current usage vs. plan limits

### Plan Usage

The usage section shows:

- **Wallet Scans** — Number of wallet scans used/available
- **TLS Scans** — Number of TLS scans used/available
- **Storage** — Data storage used/available
- **Expiration** — Plan expiration date (if applicable)

### Plan Limits

Different plans have different limits:

- **Free Plan** — Limited scans (typically 5 scans)
- **Pro Plan** — Unlimited scans
- **Enterprise Plan** — Custom limits and features

## Wallet Management

The Wallets page (`/wallets`) allows authenticated users to manage their saved wallets. It is only visible when signed in.

### Adding a Wallet

1. Navigate to **Wallets**
2. Click **"Add Wallet"**
3. Enter:
   - **Address** — Ethereum wallet address
   - **Label** — Optional friendly name
   - **Notes** — Optional notes
4. Click **"Save"**

### Viewing Wallets

The wallets list shows:

- **Label** — Friendly name (if set)
- **Address** — Ethereum address
- **Last Scanned** — Date of last scan
- **Risk Status** — Current risk level

### Wallet Details

Click on a wallet to view:

- Complete wallet information
- Scan history
- Risk assessment
- Security recommendations

### Updating a Wallet

1. Click on a wallet in the list
2. Click **"Edit"**
3. Update the label or notes
4. Click **"Save"**

### Deleting a Wallet

1. Click on a wallet in the list
2. Click **"Delete"**
3. Confirm the deletion

**Note**: Deleting a wallet does not delete scan results. Scan results are stored separately.

## Anonymous Mode

CAFE supports anonymous usage for users who don't want to create an account.

### Anonymous Features

When using CAFE anonymously, you can:

- **View scan results** — See default (pre-scanned) endpoints and any anonymous scan results tied to your session
- **Browse Discovery** — Navigate Introduction, Dashboard, Wallet scan, and TLS scan views
- **Token inspection** — Use Platform → Security to see anonymous token information

### Anonymous Limitations

- **Running new scans** — To run new wallet or TLS scans you must sign in or sign up; the interface will prompt you to create an account
- **Temporary data** — Anonymous scan results are stored only for a limited time (e.g. 30 minutes) and are not persisted
- **No wallet management** — Cannot save or manage wallets (Wallets page requires authentication)
- **No saved history** — No long-term scan history

### Anonymous vs. Authenticated

| Feature | Anonymous | Authenticated |
|---------|-----------|---------------|
| View default endpoints | ✅ | ✅ |
| View anonymous/own scan results | ✅ (temporary) | ✅ |
| Run new wallet/TLS scans | ❌ (sign-in required) | ✅ |
| Scan storage | Temporary (e.g. 30 min) | Permanent |
| Scan history | ❌ | ✅ |
| Wallet management | ❌ | ✅ |
| Plan limits | N/A | Based on plan |
| Token inspection | ✅ | ✅ |

### Switching to Authenticated

To run scans and save your results:

1. Click **"Sign In"** or **"Sign Up"** in the navigation (or when opening a new scan)
2. Create an account or sign in
3. Your previous anonymous scans will not be transferred (they expire)
4. Run new scans with your account to build your scan history

## Tips and Best Practices

### Wallet Security

1. **Scan before first use** — Check if a wallet address has been used before
2. **Avoid reusing exposed addresses** — If a public key is exposed, create a new wallet
3. **Use Account Abstraction** — Consider migrating to ERC-4337 wallets for quantum safety
4. **Multi-chain awareness** — Check risk status across all chains you use

### TLS Security

1. **Scan critical endpoints** — Regularly scan RPC nodes and API endpoints you use
2. **Monitor PQC readiness** — Check if endpoints support post-quantum cryptography
3. **Review recommendations** — Follow security recommendations from scan results
4. **Check default endpoints** — Review pre-scanned default endpoints for known issues

### Account Management

1. **Save important wallets** — Use the wallet management feature for frequently scanned addresses
2. **Monitor usage** — Check your plan usage in Settings
3. **Review scan history** — Regularly review your scan results to track security posture
4. **Upgrade plan if needed** — Consider upgrading if you hit plan limits

## Troubleshooting

### Scan Not Starting

- **Check address format** — Wallet addresses must start with `0x` and be 42 characters
- **Check URL format** — TLS endpoints must start with `https://`
- **Check plan limits** — Verify you haven't exceeded your scan limit
- **Try refreshing** — Refresh the page and try again

### Results Not Appearing

- **Wait for processing** — Scans are processed asynchronously; wait a few seconds
- **Check anonymous mode** — Anonymous scans expire after 30 minutes
- **Refresh the page** — Results may need a page refresh to appear
- **Check filters** — Ensure filters aren't hiding your results

### Authentication Issues

- **Check credentials** — Verify email and password are correct
- **Check Turnstile** — Complete the Cloudflare Turnstile verification
- **Clear browser cache** — Clear cookies and localStorage if issues persist
- **Try token refresh** — Use the Security page to refresh your token

### Network Errors

- **Check connection** — Verify your internet connection
- **Check API status** — Verify backend services are running
- **Try again later** — Temporary network issues may resolve themselves

## Support

For additional help:

- **Documentation** — See the [CAFE Introduction](./01-introduction-cafe-crypto-agility.md) for technical details
- **Backend API** — See the [Discovery README](../cafe-discovery/README.md) for API documentation
- **Issues** — Report issues in the main repository

---

## Quick Reference

### Risk Levels

- **🔴 High Risk** — Immediate action recommended
- **🟡 Medium Risk** — Action recommended
- **🟢 Low/Safe** — Acceptable security level

### NIST Security Levels

- **Level 1** — Quantum-broken (vulnerable)
- **Level 2** — Low quantum resistance
- **Level 3** — Moderate quantum resistance
- **Level 4** — High quantum resistance
- **Level 5** — PQC-ready (post-quantum secure)

### Scan Types

- **Wallet Scan** — Analyzes Ethereum wallet quantum vulnerability
- **TLS Scan** — Analyzes TLS endpoint post-quantum readiness

