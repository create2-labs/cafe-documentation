# CAFE Developer Guide

This guide provides comprehensive documentation for integrating with the CAFE Discovery API. It includes code examples in multiple programming languages for all available endpoints.


## Document versionning

- v0.1.0
  - Date: Jan 21th, 2026
  - Author: Oleg Lodygensky
  - Comments: initial version


## Table of Contents

1. [Introduction](#introduction)
2. [Authentication](#authentication)
3. [Base URL and Configuration](#base-url-and-configuration)
4. [API Endpoints](#api-endpoints)
   - [Authentication Endpoints](#authentication-endpoints)
   - [Scan Endpoints](#scan-endpoints)
   - [Result Retrieval Endpoints](#result-retrieval-endpoints)
   - [Public Endpoints](#public-endpoints)
5. [Error Handling](#error-handling)
6. [Best Practices](#best-practices)

## Introduction

The CAFE Discovery API provides REST endpoints for scanning Ethereum wallets and TLS endpoints to assess their quantum vulnerability. The API uses hybrid PQC JWT tokens (EdDSA + ML-DSA-65) for authentication and returns results in CycloneDX v1.7 CBOM format.

### Key Features

- **Unified Scan Endpoint**: Automatically detects wallet addresses vs TLS endpoints
- **Asynchronous Processing**: Scans are queued and processed in the background
- **CBOM Format**: All results are returned as Cryptographic Bill of Materials (CycloneDX v1.7)
- **Multi-Chain Support**: Scans wallets across multiple Ethereum-compatible chains
- **Post-Quantum Analysis**: Evaluates NIST security levels and quantum readiness

## Authentication

Most endpoints require JWT authentication using hybrid PQC tokens (EdDSA + ML-DSA-65). Tokens are obtained through the `/auth/signin` endpoint and must be included in the `Authorization` header:

```
Authorization: Bearer <your-jwt-token>
```

**Note**: The JWT token is in JWS JSON General Serialization format (base64url-encoded). The frontend handles token parsing, but for API clients, treat it as an opaque string.

## Base URL and Configuration

### Base URLs

- **Direct Backend**: `http://localhost:8080` (development)
- **Via NGINX**: `https://localhost/api` (production/Docker)

### Environment Variables

Set the base URL based on your deployment:

```bash
# Development (direct backend)
export CAFE_API_URL="http://localhost:8080"

# Production (via NGINX)
export CAFE_API_URL="https://your-domain.com/api"
```

## API Endpoints

### Authentication Endpoints

#### POST /auth/signup

Register a new user account. Requires Cloudflare Turnstile verification.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword",
  "confirm_password": "securepassword",
  "turnstile_token": "0.abcdefghijklmnopqrstuvwxyz..."
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "uuid",
    "email": "user@example.com"
  }
}
```

**Examples:**

<details>
<summary>cURL</summary>

```bash
curl -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword",
    "confirm_password": "securepassword",
    "turnstile_token": "0.abcdefghijklmnopqrstuvwxyz..."
  }'
```
</details>

<details>
<summary>Go</summary>

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
)

type SignupRequest struct {
    Email           string `json:"email"`
    Password        string `json:"password"`
    ConfirmPassword string `json:"confirm_password"`
    TurnstileToken  string `json:"turnstile_token"`
}

type SignupResponse struct {
    Message string `json:"message"`
    User    struct {
        ID    string `json:"id"`
        Email string `json:"email"`
    } `json:"user"`
}

func signup(email, password, turnstileToken string) (*SignupResponse, error) {
    baseURL := "http://localhost:8080"
    
    reqBody := SignupRequest{
        Email:           email,
        Password:        password,
        ConfirmPassword: password,
        TurnstileToken:  turnstileToken,
    }
    
    jsonData, err := json.Marshal(reqBody)
    if err != nil {
        return nil, err
    }
    
    resp, err := http.Post(
        baseURL+"/auth/signup",
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var result SignupResponse
    if err := json.Unmarshal(body, &result); err != nil {
        return nil, err
    }
    
    return &result, nil
}
```
</details>

<details>
<summary>Python</summary>

```python
import requests
import json

def signup(email, password, turnstile_token):
    base_url = "http://localhost:8080"
    
    payload = {
        "email": email,
        "password": password,
        "confirm_password": password,
        "turnstile_token": turnstile_token
    }
    
    response = requests.post(
        f"{base_url}/auth/signup",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    
    response.raise_for_status()
    return response.json()

# Usage
result = signup(
    "user@example.com",
    "securepassword",
    "0.abcdefghijklmnopqrstuvwxyz..."
)
print(result)
```
</details>

<details>
<summary>Java</summary>

```java
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import com.google.gson.Gson;

public class CafeClient {
    private static final String BASE_URL = "http://localhost:8080";
    private final HttpClient httpClient;
    private final Gson gson;
    
    public CafeClient() {
        this.httpClient = HttpClient.newHttpClient();
        this.gson = new Gson();
    }
    
    public SignupResponse signup(String email, String password, String turnstileToken) 
            throws Exception {
        SignupRequest request = new SignupRequest(
            email, password, password, turnstileToken
        );
        
        String jsonBody = gson.toJson(request);
        
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(BASE_URL + "/auth/signup"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();
        
        HttpResponse<String> response = httpClient.send(
            httpRequest, 
            HttpResponse.BodyHandlers.ofString()
        );
        
        return gson.fromJson(response.body(), SignupResponse.class);
    }
    
    // Inner classes for request/response
    static class SignupRequest {
        String email;
        String password;
        String confirm_password;
        String turnstile_token;
        
        SignupRequest(String email, String password, String confirmPassword, 
                     String turnstileToken) {
            this.email = email;
            this.password = password;
            this.confirm_password = confirmPassword;
            this.turnstile_token = turnstileToken;
        }
    }
    
    static class SignupResponse {
        String message;
        User user;
        
        static class User {
            String id;
            String email;
        }
    }
}
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:8080';

async function signup(email, password, turnstileToken) {
    try {
        const response = await axios.post(`${BASE_URL}/auth/signup`, {
            email: email,
            password: password,
            confirm_password: password,
            turnstile_token: turnstileToken
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        return response.data;
    } catch (error) {
        console.error('Signup error:', error.response?.data || error.message);
        throw error;
    }
}

// Usage
signup('user@example.com', 'securepassword', '0.abcdefghijklmnopqrstuvwxyz...')
    .then(result => console.log(result))
    .catch(error => console.error(error));
```
</details>

#### POST /auth/signin

Sign in and receive a hybrid PQC JWT token. Requires Cloudflare Turnstile verification.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword",
  "turnstile_token": "0.abcdefghijklmnopqrstuvwxyz..."
}
```

**Response:**
```json
{
  "token": "eyJwYXlsb2FkIjoi...",
  "user": {
    "id": "uuid",
    "email": "user@example.com"
  }
}
```

**Examples:**

<details>
<summary>cURL</summary>

```bash
# Sign in and save token to variable
TOKEN=$(curl -s  -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword",
    "confirm_password": "securepassword",
    "turnstile_token": "0.abcdefghijklmnopqrstuvwxyz..."
  }'| jq -r '.token')
  
echo "Token stored: $TOKEN"

# Use the token in subsequent API calls
curl -X POST http://localhost:8080/discovery/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
  }'

# Or save token to file for persistence
echo "$TOKEN" > ~/.cafe_token
# Later, load token from file
TOKEN=$(cat ~/.cafe_token)
```
</details>

<details>
<summary>Go</summary>

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/user"
    "path/filepath"
)

type SigninRequest struct {
    Email          string `json:"email"`
    Password       string `json:"password"`
    TurnstileToken string `json:"turnstile_token"`
}

type SigninResponse struct {
    Token string `json:"token"`
    User  struct {
        ID    string `json:"id"`
        Email string `json:"email"`
    } `json:"user"`
}

// Sign in and return token
func signin(email, password, turnstileToken string) (string, error) {
    baseURL := "http://localhost:8080"
    
    reqBody := SigninRequest{
        Email:          email,
        Password:       password,
        TurnstileToken: turnstileToken,
    }
    
    jsonData, err := json.Marshal(reqBody)
    if err != nil {
        return "", err
    }
    
    resp, err := http.Post(
        baseURL+"/auth/signin",
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }
    
    var result SigninResponse
    if err := json.Unmarshal(body, &result); err != nil {
        return "", err
    }
    
    return result.Token, nil
}

// Save token to file
func saveToken(token string) error {
    usr, err := user.Current()
    if err != nil {
        return err
    }
    
    tokenFile := filepath.Join(usr.HomeDir, ".cafe_token")
    return os.WriteFile(tokenFile, []byte(token), 0600)
}

// Load token from file
func loadToken() (string, error) {
    usr, err := user.Current()
    if err != nil {
        return "", err
    }
    
    tokenFile := filepath.Join(usr.HomeDir, ".cafe_token")
    data, err := os.ReadFile(tokenFile)
    if err != nil {
        return "", err
    }
    
    return string(data), nil
}

// Example usage with token storage
func main() {
    // Sign in and get token
    token, err := signin(
        "user@example.com",
        "securepassword",
        "0.abcdefghijklmnopqrstuvwxyz...",
    )
    if err != nil {
        fmt.Printf("Signin error: %v\n", err)
        return
    }
    
    // Save token for later use
    if err := saveToken(token); err != nil {
        fmt.Printf("Error saving token: %v\n", err)
    } else {
        fmt.Println("Token saved successfully")
    }
    
    // Later, load token from file
    savedToken, err := loadToken()
    if err != nil {
        fmt.Printf("Error loading token: %v\n", err)
        return
    }
    
    // Use token in API calls
    fmt.Printf("Using token: %s...\n", savedToken[:20])
    // ... use savedToken in API requests
}
```
</details>

<details>
<summary>Python</summary>

```python
import requests
import os
from pathlib import Path

def signin(email, password, turnstile_token):
    base_url = "http://localhost:8080"
    
    payload = {
        "email": email,
        "password": password,
        "turnstile_token": turnstile_token
    }
    
    response = requests.post(
        f"{base_url}/auth/signin",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    
    response.raise_for_status()
    data = response.json()
    return data["token"], data["user"]

def save_token(token):
    """Save token to file"""
    token_file = Path.home() / ".cafe_token"
    token_file.write_text(token)
    # Set file permissions to read/write for owner only
    os.chmod(token_file, 0o600)

def load_token():
    """Load token from file"""
    token_file = Path.home() / ".cafe_token"
    if token_file.exists():
        return token_file.read_text().strip()
    return None

# Usage: Sign in and store token
token, user = signin(
    "user@example.com",
    "securepassword",
    "0.abcdefghijklmnopqrstuvwxyz..."
)

# Save token for later use
save_token(token)
print(f"Token saved for user: {user['email']}")

# Later, load token and use it
saved_token = load_token()
if saved_token:
    # Use token in API calls
    headers = {
        "Authorization": f"Bearer {saved_token}",
        "Content-Type": "application/json"
    }
    # ... make API calls with headers
```
</details>

<details>
<summary>Java</summary>

```java
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;

public class CafeClient {
    private static final String BASE_URL = "http://localhost:8080";
    private final HttpClient httpClient;
    private final Gson gson;
    private String token; // Store token in memory
    
    public CafeClient() {
        this.httpClient = HttpClient.newHttpClient();
        this.gson = new Gson();
    }
    
    public String signin(String email, String password, String turnstileToken) 
            throws Exception {
        SigninRequest request = new SigninRequest(email, password, turnstileToken);
        String jsonBody = gson.toJson(request);
        
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(BASE_URL + "/auth/signin"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();
        
        HttpResponse<String> response = httpClient.send(
            httpRequest, 
            HttpResponse.BodyHandlers.ofString()
        );
        
        SigninResponse signinResponse = gson.fromJson(
            response.body(), 
            SigninResponse.class
        );
        
        // Store token in memory
        this.token = signinResponse.token;
        
        return this.token;
    }
    
    // Save token to file
    public void saveToken(String token) throws IOException {
        Path tokenFile = Paths.get(System.getProperty("user.home"), ".cafe_token");
        Files.write(tokenFile, token.getBytes());
        
        // Set file permissions (Unix-like systems)
        try {
            Files.setPosixFilePermissions(
                tokenFile, 
                PosixFilePermissions.fromString("rw-------")
            );
        } catch (UnsupportedOperationException e) {
            // Windows doesn't support PosixFilePermissions
        }
    }
    
    // Load token from file
    public String loadToken() throws IOException {
        Path tokenFile = Paths.get(System.getProperty("user.home"), ".cafe_token");
        if (Files.exists(tokenFile)) {
            String token = new String(Files.readAllBytes(tokenFile));
            this.token = token.trim();
            return this.token;
        }
        return null;
    }
    
    // Get stored token
    public String getToken() {
        return this.token;
    }
    
    // Use token in API calls
    public HttpRequest.Builder authenticatedRequest(String endpoint) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(BASE_URL + endpoint))
            .header("Authorization", "Bearer " + this.token);
        
        return builder;
    }
    
    static class SigninRequest {
        String email;
        String password;
        String turnstile_token;
        
        SigninRequest(String email, String password, String turnstileToken) {
            this.email = email;
            this.password = password;
            this.turnstile_token = turnstileToken;
        }
    }
    
    static class SigninResponse {
        String token;
        User user;
    }
    
    // Usage example
    public static void main(String[] args) throws Exception {
        CafeClient client = new CafeClient();
        
        // Sign in
        String token = client.signin(
            "user@example.com",
            "securepassword",
            "0.abcdefghijklmnopqrstuvwxyz..."
        );
        
        // Save token
        client.saveToken(token);
        System.out.println("Token saved: " + token.substring(0, 20) + "...");
        
        // Later, load token
        String loadedToken = client.loadToken();
        if (loadedToken != null) {
            System.out.println("Token loaded successfully");
            // Use client.getToken() or client.authenticatedRequest() for API calls
        }
    }
}
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');

const BASE_URL = 'http://localhost:8080';

// Store token in memory
let token = null;

async function signin(email, password, turnstileToken) {
    try {
        const response = await axios.post(`${BASE_URL}/auth/signin`, {
            email: email,
            password: password,
            turnstile_token: turnstileToken
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        // Store token in memory
        token = response.data.token;
        
        return {
            token: response.data.token,
            user: response.data.user
        };
    } catch (error) {
        console.error('Signin error:', error.response?.data || error.message);
        throw error;
    }
}

// Save token to file
async function saveToken(token) {
    const tokenFile = path.join(os.homedir(), '.cafe_token');
    await fs.writeFile(tokenFile, token, { mode: 0o600 });
    console.log('Token saved to', tokenFile);
}

// Load token from file
async function loadToken() {
    const tokenFile = path.join(os.homedir(), '.cafe_token');
    try {
        const data = await fs.readFile(tokenFile, 'utf8');
        token = data.trim();
        return token;
    } catch (error) {
        if (error.code === 'ENOENT') {
            return null;
        }
        throw error;
    }
}

// Get stored token
function getToken() {
    return token;
}

// Usage
(async () => {
    // Sign in and store token
    const { token: authToken, user } = await signin(
        'user@example.com',
        'securepassword',
        '0.abcdefghijklmnopqrstuvwxyz...'
    );
    
    // Save token to file
    await saveToken(authToken);
    console.log('Authenticated as:', user.email);
    
    // Later, load token from file
    const loadedToken = await loadToken();
    if (loadedToken) {
        console.log('Token loaded from file');
        // Use getToken() or loadedToken in API calls
    }
})();
```
</details>

### Scan Endpoints

#### POST /discovery/scan

Unified scan endpoint that automatically detects whether the request is for a wallet scan or TLS endpoint scan. Requires authentication. The scan is processed asynchronously via NATS.

**For Wallet Scans:**

**Request Body:**
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
}
```

**Response:**
```json
{
  "message": "scan queued successfully",
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "type": "wallet",
  "status": "processing"
}
```

**For TLS Endpoint Scans:**

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "message": "scan queued successfully",
  "endpoint": "https://example.com",
  "type": "tls",
  "status": "processing"
}
```

**Examples:**

<details>
<summary>cURL</summary>

```bash
# Scan a wallet address
curl -X POST http://localhost:8080/discovery/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
  }'

# Scan a TLS endpoint
curl -X POST http://localhost:8080/discovery/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "url": "https://example.com"
  }'
```
</details>

<details>
<summary>Go</summary>

```go
type ScanRequest struct {
    Address *string `json:"address,omitempty"`
    URL     *string `json:"url,omitempty"`
}

type ScanResponse struct {
    Message  string `json:"message"`
    Address  string `json:"address,omitempty"`
    Endpoint string `json:"endpoint,omitempty"`
    Type     string `json:"type"`
    Status   string `json:"status"`
}

func scanWallet(token, address string) (*ScanResponse, error) {
    baseURL := "http://localhost:8080"
    
    reqBody := ScanRequest{Address: &address}
    jsonData, err := json.Marshal(reqBody)
    if err != nil {
        return nil, err
    }
    
    req, err := http.NewRequest("POST", baseURL+"/discovery/scan", 
        bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+token)
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var result ScanResponse
    if err := json.Unmarshal(body, &result); err != nil {
        return nil, err
    }
    
    return &result, nil
}

func scanTLS(token, url string) (*ScanResponse, error) {
    baseURL := "http://localhost:8080"
    
    reqBody := ScanRequest{URL: &url}
    jsonData, err := json.Marshal(reqBody)
    if err != nil {
        return nil, err
    }
    
    req, err := http.NewRequest("POST", baseURL+"/discovery/scan", 
        bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+token)
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var result ScanResponse
    if err := json.Unmarshal(body, &result); err != nil {
        return nil, err
    }
    
    return &result, nil
}
```
</details>

<details>
<summary>Python</summary>

```python
def scan_wallet(token, address):
    base_url = "http://localhost:8080"
    
    payload = {"address": address}
    
    response = requests.post(
        f"{base_url}/discovery/scan",
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
    )
    
    response.raise_for_status()
    return response.json()

def scan_tls(token, url):
    base_url = "http://localhost:8080"
    
    payload = {"url": url}
    
    response = requests.post(
        f"{base_url}/discovery/scan",
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
    )
    
    response.raise_for_status()
    return response.json()

# Usage
result = scan_wallet(token, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
print(result)

result = scan_tls(token, "https://example.com")
print(result)
```
</details>

<details>
<summary>Java</summary>

```java
public ScanResponse scanWallet(String token, String address) throws Exception {
    ScanRequest request = new ScanRequest();
    request.address = address;
    
    String jsonBody = gson.toJson(request);
    
    HttpRequest httpRequest = HttpRequest.newBuilder()
        .uri(URI.create(BASE_URL + "/discovery/scan"))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer " + token)
        .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
        .build();
    
    HttpResponse<String> response = httpClient.send(
        httpRequest, 
        HttpResponse.BodyHandlers.ofString()
    );
    
    return gson.fromJson(response.body(), ScanResponse.class);
}

public ScanResponse scanTLS(String token, String url) throws Exception {
    ScanRequest request = new ScanRequest();
    request.url = url;
    
    String jsonBody = gson.toJson(request);
    
    HttpRequest httpRequest = HttpRequest.newBuilder()
        .uri(URI.create(BASE_URL + "/discovery/scan"))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer " + token)
        .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
        .build();
    
    HttpResponse<String> response = httpClient.send(
        httpRequest, 
        HttpResponse.BodyHandlers.ofString()
    );
    
    return gson.fromJson(response.body(), ScanResponse.class);
}

static class ScanRequest {
    String address;
    String url;
}

static class ScanResponse {
    String message;
    String address;
    String endpoint;
    String type;
    String status;
}
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
async function scanWallet(token, address) {
    try {
        const response = await axios.post(
            `${BASE_URL}/discovery/scan`,
            { address: address },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                }
            }
        );
        
        return response.data;
    } catch (error) {
        console.error('Scan error:', error.response?.data || error.message);
        throw error;
    }
}

async function scanTLS(token, url) {
    try {
        const response = await axios.post(
            `${BASE_URL}/discovery/scan`,
            { url: url },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                }
            }
        );
        
        return response.data;
    } catch (error) {
        console.error('Scan error:', error.response?.data || error.message);
        throw error;
    }
}

// Usage
const walletResult = await scanWallet(
    token, 
    '0x742d35Cc6634C0532925a3b844Bc454e4438f44e'
);
console.log(walletResult);

const tlsResult = await scanTLS(token, 'https://example.com');
console.log(tlsResult);
```
</details>

### Result Retrieval Endpoints

#### GET /discovery/scans

Returns paginated list of CBOMs (Cryptographic Bill of Materials) for wallet scans for the authenticated user.

**Query Parameters:**
- `limit` (optional): Number of results per page (default: 20)
- `offset` (optional): Number of results to skip (default: 0)

**Response:**
```json
{
  "results": [
    {
      "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      "type": "EOA",
      "algorithm": "ECDSA-secp256k1",
      "nist_level": 1,
      "key_exposed": true,
      "risk_score": 0.85,
      "networks": ["ethereum-mainnet", "polygon"],
      "scanned_at": "2025-01-15T10:30:00Z",
      "cbom": {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
          "timestamp": "2025-01-15T10:30:00Z"
        },
        "type": "wallet",
        "components": [...]
      }
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0,
  "count": 1
}
```

**Examples:**

<details>
<summary>cURL</summary>

```bash
# List wallet scans with pagination
curl -X GET "http://localhost:8080/discovery/scans?limit=10&offset=0" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Via NGINX (HTTPS)
curl -k "https://localhost/api/discovery/scans?limit=10&offset=0" \
  -H "Authorization: Bearer $TOKEN" | jq .
```
</details>

<details>
<summary>Go</summary>

```go
type WalletScansResponse struct {
    Results []WalletScanResult `json:"results"`
    Total   int                `json:"total"`
    Limit   int                `json:"limit"`
    Offset  int                `json:"offset"`
    Count   int                `json:"count"`
}

type WalletScanResult struct {
    Address     string    `json:"address"`
    Type        string    `json:"type"`
    Algorithm   string    `json:"algorithm"`
    NISTLevel   int       `json:"nist_level"`
    KeyExposed  bool      `json:"key_exposed"`
    RiskScore   float64   `json:"risk_score"`
    Networks    []string  `json:"networks"`
    ScannedAt   string    `json:"scanned_at"`
    CBOM        interface{} `json:"cbom"`
}

func listWalletScans(token string, limit, offset int) (*WalletScansResponse, error) {
    baseURL := "http://localhost:8080"
    url := fmt.Sprintf("%s/discovery/scans?limit=%d&offset=%d", 
        baseURL, limit, offset)
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Authorization", "Bearer "+token)
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var result WalletScansResponse
    if err := json.Unmarshal(body, &result); err != nil {
        return nil, err
    }
    
    return &result, nil
}
```
</details>

<details>
<summary>Python</summary>

```python
def list_wallet_scans(token, limit=20, offset=0):
    base_url = "http://localhost:8080"
    
    params = {
        "limit": limit,
        "offset": offset
    }
    
    response = requests.get(
        f"{base_url}/discovery/scans",
        params=params,
        headers={
            "Authorization": f"Bearer {token}"
        }
    )
    
    response.raise_for_status()
    return response.json()

# Usage
scans = list_wallet_scans(token, limit=10, offset=0)
print(f"Total scans: {scans['total']}")
for scan in scans['results']:
    print(f"Address: {scan['address']}, Risk: {scan['risk_score']}")
```
</details>

<details>
<summary>Java</summary>

```java
public WalletScansResponse listWalletScans(String token, int limit, int offset) 
        throws Exception {
    String url = String.format(
        "%s/discovery/scans?limit=%d&offset=%d", 
        BASE_URL, limit, offset
    );
    
    HttpRequest httpRequest = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .header("Authorization", "Bearer " + token)
        .GET()
        .build();
    
    HttpResponse<String> response = httpClient.send(
        httpRequest, 
        HttpResponse.BodyHandlers.ofString()
    );
    
    return gson.fromJson(response.body(), WalletScansResponse.class);
}

static class WalletScansResponse {
    List<WalletScanResult> results;
    int total;
    int limit;
    int offset;
    int count;
}

static class WalletScanResult {
    String address;
    String type;
    String algorithm;
    int nist_level;
    boolean key_exposed;
    double risk_score;
    List<String> networks;
    String scanned_at;
    Object cbom;
}
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
async function listWalletScans(token, limit = 20, offset = 0) {
    try {
        const response = await axios.get(
            `${BASE_URL}/discovery/scans`,
            {
                params: { limit, offset },
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            }
        );
        
        return response.data;
    } catch (error) {
        console.error('List scans error:', error.response?.data || error.message);
        throw error;
    }
}

// Usage
const scans = await listWalletScans(token, 10, 0);
console.log(`Total scans: ${scans.total}`);
scans.results.forEach(scan => {
    console.log(`Address: ${scan.address}, Risk: ${scan.risk_score}`);
});
```
</details>

#### GET /discovery/tls/scans

Returns paginated list of CBOMs for TLS endpoint scans for the authenticated user.

**Query Parameters:**
- `limit` (optional): Number of results per page (default: 20)
- `offset` (optional): Number of results to skip (default: 0)

**Examples:**

<details>
<summary>cURL</summary>

```bash
curl -X GET "http://localhost:8080/discovery/tls/scans?limit=10&offset=0" \
  -H "Authorization: Bearer $TOKEN" | jq .
```
</details>

<details>
<summary>Go</summary>

```go
func listTLSScans(token string, limit, offset int) (*TLSScansResponse, error) {
    baseURL := "http://localhost:8080"
    url := fmt.Sprintf("%s/discovery/tls/scans?limit=%d&offset=%d", 
        baseURL, limit, offset)
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Authorization", "Bearer "+token)
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var result TLSScansResponse
    if err := json.Unmarshal(body, &result); err != nil {
        return nil, err
    }
    
    return &result, nil
}
```
</details>

<details>
<summary>Python</summary>

```python
def list_tls_scans(token, limit=20, offset=0):
    base_url = "http://localhost:8080"
    
    params = {
        "limit": limit,
        "offset": offset
    }
    
    response = requests.get(
        f"{base_url}/discovery/tls/scans",
        params=params,
        headers={
            "Authorization": f"Bearer {token}"
        }
    )
    
    response.raise_for_status()
    return response.json()
```
</details>

<details>
<summary>Java</summary>

```java
public TLSScansResponse listTLSScans(String token, int limit, int offset) 
        throws Exception {
    String url = String.format(
        "%s/discovery/tls/scans?limit=%d&offset=%d", 
        BASE_URL, limit, offset
    );
    
    HttpRequest httpRequest = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .header("Authorization", "Bearer " + token)
        .GET()
        .build();
    
    HttpResponse<String> response = httpClient.send(
        httpRequest, 
        HttpResponse.BodyHandlers.ofString()
    );
    
    return gson.fromJson(response.body(), TLSScansResponse.class);
}
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
async function listTLSScans(token, limit = 20, offset = 0) {
    try {
        const response = await axios.get(
            `${BASE_URL}/discovery/tls/scans`,
            {
                params: { limit, offset },
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            }
        );
        
        return response.data;
    } catch (error) {
        console.error('List TLS scans error:', error.response?.data || error.message);
        throw error;
    }
}
```
</details>

#### GET /discovery/cbom/*

Returns a CBOM (Cryptographic Bill of Materials) JSON record for a wallet address or TLS endpoint. Automatically detects the type based on the parameter format.

**Path Parameters:**
- `*`: Either:
  - Ethereum wallet address (e.g., `0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb`)
  - TLS endpoint URL (must be URL-encoded, e.g., `https%3A%2F%2Fexample.com`)

**Examples:**

<details>
<summary>cURL</summary>

```bash
# Get CBOM for wallet address
curl "http://localhost:8080/discovery/cbom/0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Get CBOM for TLS endpoint (URL-encoded)
curl "http://localhost:8080/discovery/cbom/https%3A%2F%2Fexample.com" \
  -H "Authorization: Bearer $TOKEN" | jq .
```
</details>

<details>
<summary>Go</summary>

```go
import "net/url"

func getCBOM(token, identifier string) (interface{}, error) {
    baseURL := "http://localhost:8080"
    
    // URL-encode if it's a URL (starts with http:// or https://)
    var path string
    if strings.HasPrefix(identifier, "http://") || 
       strings.HasPrefix(identifier, "https://") {
        path = url.QueryEscape(identifier)
    } else {
        path = identifier
    }
    
    url := fmt.Sprintf("%s/discovery/cbom/%s", baseURL, path)
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Authorization", "Bearer "+token)
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var result map[string]interface{}
    if err := json.Unmarshal(body, &result); err != nil {
        return nil, err
    }
    
    return result, nil
}
```
</details>

<details>
<summary>Python</summary>

```python
from urllib.parse import quote

def get_cbom(token, identifier):
    base_url = "http://localhost:8080"
    
    # URL-encode if it's a URL
    if identifier.startswith(('http://', 'https://')):
        path = quote(identifier, safe='')
    else:
        path = identifier
    
    response = requests.get(
        f"{base_url}/discovery/cbom/{path}",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )
    
    response.raise_for_status()
    return response.json()

# Usage
wallet_cbom = get_cbom(token, "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb")
tls_cbom = get_cbom(token, "https://example.com")
```
</details>

<details>
<summary>Java</summary>

```java
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public Object getCBOM(String token, String identifier) throws Exception {
    String path;
    if (identifier.startsWith("http://") || identifier.startsWith("https://")) {
        path = URLEncoder.encode(identifier, StandardCharsets.UTF_8);
    } else {
        path = identifier;
    }
    
    String url = BASE_URL + "/discovery/cbom/" + path;
    
    HttpRequest httpRequest = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .header("Authorization", "Bearer " + token)
        .GET()
        .build();
    
    HttpResponse<String> response = httpClient.send(
        httpRequest, 
        HttpResponse.BodyHandlers.ofString()
    );
    
    return gson.fromJson(response.body(), Object.class);
}
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
async function getCBOM(token, identifier) {
    try {
        // URL-encode if it's a URL
        let path;
        if (identifier.startsWith('http://') || identifier.startsWith('https://')) {
            path = encodeURIComponent(identifier);
        } else {
            path = identifier;
        }
        
        const response = await axios.get(
            `${BASE_URL}/discovery/cbom/${path}`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            }
        );
        
        return response.data;
    } catch (error) {
        console.error('Get CBOM error:', error.response?.data || error.message);
        throw error;
    }
}

// Usage
const walletCBOM = await getCBOM(
    token, 
    '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'
);
const tlsCBOM = await getCBOM(token, 'https://example.com');
```
</details>

### Public Endpoints

#### GET /discovery/rpcs

Returns the list of configured RPC endpoints. No authentication required.

**Response:**
```json
{
  "blockchains": [
    {
      "name": "ethereum-mainnet",
      "rpc": "https://ethereum-rpc.publicnode.com"
    },
    {
      "name": "polygon",
      "rpc": "https://polygon.llamarpc.com"
    }
  ],
  "count": 6
}
```

**Examples:**

<details>
<summary>cURL</summary>

```bash
curl http://localhost:8080/discovery/rpcs | jq .
```
</details>

<details>
<summary>Go</summary>

```go
type RPCsResponse struct {
    Blockchains []Blockchain `json:"blockchains"`
    Count       int          `json:"count"`
}

type Blockchain struct {
    Name string `json:"name"`
    RPC  string `json:"rpc"`
}

func getRPCs() (*RPCsResponse, error) {
    baseURL := "http://localhost:8080"
    
    resp, err := http.Get(baseURL + "/discovery/rpcs")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var result RPCsResponse
    if err := json.Unmarshal(body, &result); err != nil {
        return nil, err
    }
    
    return &result, nil
}
```
</details>

<details>
<summary>Python</summary>

```python
def get_rpcs():
    base_url = "http://localhost:8080"
    
    response = requests.get(f"{base_url}/discovery/rpcs")
    response.raise_for_status()
    return response.json()

# Usage
rpcs = get_rpcs()
for blockchain in rpcs['blockchains']:
    print(f"{blockchain['name']}: {blockchain['rpc']}")
```
</details>

<details>
<summary>Java</summary>

```java
public RPCsResponse getRPCs() throws Exception {
    HttpRequest httpRequest = HttpRequest.newBuilder()
        .uri(URI.create(BASE_URL + "/discovery/rpcs"))
        .GET()
        .build();
    
    HttpResponse<String> response = httpClient.send(
        httpRequest, 
        HttpResponse.BodyHandlers.ofString()
    );
    
    return gson.fromJson(response.body(), RPCsResponse.class);
}
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
async function getRPCs() {
    try {
        const response = await axios.get(`${BASE_URL}/discovery/rpcs`);
        return response.data;
    } catch (error) {
        console.error('Get RPCs error:', error.response?.data || error.message);
        throw error;
    }
}
```
</details>

#### GET /health

Health check endpoint. No authentication required.

**Response:**
```json
{
  "status": "ok",
  "app_name": "Cafe Discovery Service",
  "version": "1.0.0",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

**Examples:**

<details>
<summary>cURL</summary>

```bash
curl http://localhost:8080/health | jq .
```
</details>

<details>
<summary>Go</summary>

```go
type HealthResponse struct {
    Status    string `json:"status"`
    AppName   string `json:"app_name"`
    Version   string `json:"version"`
    Timestamp string `json:"timestamp"`
}

func checkHealth() (*HealthResponse, error) {
    baseURL := "http://localhost:8080"
    
    resp, err := http.Get(baseURL + "/health")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    var result HealthResponse
    if err := json.Unmarshal(body, &result); err != nil {
        return nil, err
    }
    
    return &result, nil
}
```
</details>

<details>
<summary>Python</summary>

```python
def check_health():
    base_url = "http://localhost:8080"
    
    response = requests.get(f"{base_url}/health")
    response.raise_for_status()
    return response.json()

# Usage
health = check_health()
print(f"Status: {health['status']}, Version: {health['version']}")
```
</details>

<details>
<summary>Java</summary>

```java
public HealthResponse checkHealth() throws Exception {
    HttpRequest httpRequest = HttpRequest.newBuilder()
        .uri(URI.create(BASE_URL + "/health"))
        .GET()
        .build();
    
    HttpResponse<String> response = httpClient.send(
        httpRequest, 
        HttpResponse.BodyHandlers.ofString()
    );
    
    return gson.fromJson(response.body(), HealthResponse.class);
}
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
async function checkHealth() {
    try {
        const response = await axios.get(`${BASE_URL}/health`);
        return response.data;
    } catch (error) {
        console.error('Health check error:', error.response?.data || error.message);
        throw error;
    }
}
```
</details>

#### GET /metrics

Prometheus metrics endpoint. Exposes metrics in Prometheus format for scraping. No authentication required.

**Examples:**

<details>
<summary>cURL</summary>

```bash
curl http://localhost:8080/metrics
```
</details>

<details>
<summary>Go</summary>

```go
func getMetrics() (string, error) {
    baseURL := "http://localhost:8080"
    
    resp, err := http.Get(baseURL + "/metrics")
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }
    
    return string(body), nil
}
```
</details>

<details>
<summary>Python</summary>

```python
def get_metrics():
    base_url = "http://localhost:8080"
    
    response = requests.get(f"{base_url}/metrics")
    response.raise_for_status()
    return response.text

# Usage
metrics = get_metrics()
print(metrics)
```
</details>

<details>
<summary>Java</summary>

```java
public String getMetrics() throws Exception {
    HttpRequest httpRequest = HttpRequest.newBuilder()
        .uri(URI.create(BASE_URL + "/metrics"))
        .GET()
        .build();
    
    HttpResponse<String> response = httpClient.send(
        httpRequest, 
        HttpResponse.BodyHandlers.ofString()
    );
    
    return response.body();
}
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
async function getMetrics() {
    try {
        const response = await axios.get(`${BASE_URL}/metrics`, {
            responseType: 'text'
        });
        return response.data;
    } catch (error) {
        console.error('Get metrics error:', error.response?.data || error.message);
        throw error;
    }
}
```
</details>

## Error Handling

The API returns standard HTTP status codes:

- **200 OK**: Request successful
- **201 Created**: Resource created successfully
- **400 Bad Request**: Invalid request parameters
- **401 Unauthorized**: Missing or invalid authentication token
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error
- **503 Service Unavailable**: Service temporarily unavailable

**Error Response Format:**
```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": {}
}
```

**Examples:**

<details>
<summary>Go</summary>

```go
func handleError(resp *http.Response) error {
    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
        return nil
    }
    
    body, _ := io.ReadAll(resp.Body)
    
    var errorResp struct {
        Error   string `json:"error"`
        Code    string `json:"code"`
        Details interface{} `json:"details"`
    }
    
    json.Unmarshal(body, &errorResp)
    
    return fmt.Errorf("API error [%d]: %s (code: %s)", 
        resp.StatusCode, errorResp.Error, errorResp.Code)
}
```
</details>

<details>
<summary>Python</summary>

```python
def handle_error(response):
    if response.status_code >= 200 and response.status_code < 300:
        return
    
    try:
        error_data = response.json()
        raise Exception(
            f"API error [{response.status_code}]: "
            f"{error_data.get('error', 'Unknown error')} "
            f"(code: {error_data.get('code', 'UNKNOWN')})"
        )
    except ValueError:
        raise Exception(f"HTTP {response.status_code}: {response.text}")
```
</details>

<details>
<summary>JavaScript (Node.js)</summary>

```javascript
function handleError(error) {
    if (error.response) {
        const { status, data } = error.response;
        throw new Error(
            `API error [${status}]: ${data.error || 'Unknown error'} ` +
            `(code: ${data.code || 'UNKNOWN'})`
        );
    } else {
        throw error;
    }
}
```
</details>

## Best Practices

### 1. Token Management

- Store tokens securely (environment variables, secure storage)
- Handle token expiration gracefully
- Refresh tokens when needed
- Never commit tokens to version control

### 2. Asynchronous Processing

- Scans are processed asynchronously
- After submitting a scan, poll for results or use webhooks (if available)
- Wait a few seconds before checking results

### 3. Rate Limiting

- Respect rate limits (10 requests/second per IP)
- Implement exponential backoff for retries
- Use connection pooling for multiple requests

### 4. Error Handling

- Always check HTTP status codes
- Implement retry logic for transient errors
- Log errors for debugging
- Provide meaningful error messages to users

### 5. CBOM Processing

- CBOMs follow CycloneDX v1.7 format
- Parse the `cbom.components` array for detailed cryptographic information
- Use NIST levels for risk assessment
- Check `key_exposed` and `quantum_vulnerable` flags

### 6. URL Encoding

- Always URL-encode TLS endpoint URLs when using `/discovery/cbom/*`
- Wallet addresses don't need encoding
- Use proper URL encoding libraries

### 7. Testing

- Use development Turnstile keys for testing
- Test with both wallet addresses and TLS endpoints
- Verify error handling with invalid inputs
- Test pagination for list endpoints

## Complete Example: Wallet Scan Workflow

Here's a complete example showing the full workflow:

<details>
<summary>Python Complete Example</summary>

```python
import requests
import time
from urllib.parse import quote

class CafeDiscoveryClient:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.token = None
    
    def signin(self, email, password, turnstile_token):
        """Sign in and store token"""
        response = requests.post(
            f"{self.base_url}/auth/signin",
            json={
                "email": email,
                "password": password,
                "turnstile_token": turnstile_token
            }
        )
        response.raise_for_status()
        self.token = response.json()["token"]
        return self.token
    
    def scan_wallet(self, address):
        """Submit a wallet scan"""
        response = requests.post(
            f"{self.base_url}/discovery/scan",
            json={"address": address},
            headers={"Authorization": f"Bearer {self.token}"}
        )
        response.raise_for_status()
        return response.json()
    
    def get_cbom(self, identifier):
        """Get CBOM for wallet or TLS endpoint"""
        if identifier.startswith(('http://', 'https://')):
            path = quote(identifier, safe='')
        else:
            path = identifier
        
        response = requests.get(
            f"{self.base_url}/discovery/cbom/{path}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        response.raise_for_status()
        return response.json()
    
    def wait_for_scan(self, identifier, max_wait=30, poll_interval=2):
        """Wait for scan to complete and return CBOM"""
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                cbom = self.get_cbom(identifier)
                return cbom
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    # Scan not ready yet, wait and retry
                    time.sleep(poll_interval)
                    continue
                raise
        
        raise TimeoutError(f"Scan did not complete within {max_wait} seconds")

# Usage
client = CafeDiscoveryClient()

# Sign in
client.signin(
    "user@example.com",
    "password",
    "turnstile_token_here"
)

# Scan a wallet
result = client.scan_wallet("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
print(f"Scan queued: {result}")

# Wait for results
cbom = client.wait_for_scan("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
print(f"Risk Score: {cbom['risk_score']}")
print(f"NIST Level: {cbom['nist_level']}")
print(f"Key Exposed: {cbom['key_exposed']}")
```
</details>

<details>
<summary>JavaScript (Node.js) Complete Example</summary>

```javascript
const axios = require('axios');

class CafeDiscoveryClient {
    constructor(baseURL = 'http://localhost:8080') {
        this.baseURL = baseURL;
        this.token = null;
    }
    
    async signin(email, password, turnstileToken) {
        const response = await axios.post(`${this.baseURL}/auth/signin`, {
            email,
            password,
            turnstile_token: turnstileToken
        });
        
        this.token = response.data.token;
        return this.token;
    }
    
    async scanWallet(address) {
        const response = await axios.post(
            `${this.baseURL}/discovery/scan`,
            { address },
            {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            }
        );
        
        return response.data;
    }
    
    async getCBOM(identifier) {
        const path = identifier.startsWith('http') 
            ? encodeURIComponent(identifier)
            : identifier;
        
        const response = await axios.get(
            `${this.baseURL}/discovery/cbom/${path}`,
            {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            }
        );
        
        return response.data;
    }
    
    async waitForScan(identifier, maxWait = 30000, pollInterval = 2000) {
        const startTime = Date.now();
        
        while (Date.now() - startTime < maxWait) {
            try {
                return await this.getCBOM(identifier);
            } catch (error) {
                if (error.response?.status === 404) {
                    await new Promise(resolve => setTimeout(resolve, pollInterval));
                    continue;
                }
                throw error;
            }
        }
        
        throw new Error(`Scan did not complete within ${maxWait}ms`);
    }
}

// Usage
(async () => {
    const client = new CafeDiscoveryClient();
    
    await client.signin('user@example.com', 'password', 'turnstile_token');
    
    const result = await client.scanWallet('0x742d35Cc6634C0532925a3b844Bc454e4438f44e');
    console.log('Scan queued:', result);
    
    const cbom = await client.waitForScan('0x742d35Cc6634C0532925a3b844Bc454e4438f44e');
    console.log('Risk Score:', cbom.risk_score);
    console.log('NIST Level:', cbom.nist_level);
    console.log('Key Exposed:', cbom.key_exposed);
})();
```
</details>

## Additional Resources

- [CAFE Introduction](./01-introduction-cafe-crypto-agility.md) - Overview of CAFE and crypto-agility
- [CAFE User Guide](./02-cafe-user-guide.md) - Frontend usage guide
- [Discovery README](../cafe-discovery/README.md) - Complete backend documentation
- [CycloneDX CBOM Specification](https://cyclonedx.org/capabilities/cbom/) - CBOM format documentation
