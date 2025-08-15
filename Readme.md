# Password Safe Box Deployment Guide

This is a secure credential storage application built as a Cloudflare Worker. It provides a web interface to store and manage login credentials with encryption and authentication.

## Features

- Secure storage of login credentials using Cloudflare Workers KV
- JWT-based authentication system
- Client-side encryption of passwords
- Login attempt logging
- Responsive web interface

## Prerequisites

- A Cloudflare account
- [Wrangler CLI](https://developers.cloudflare.com/workers/cli-wrangler) installed
- Node.js and npm installed

## Deployment Steps

### 1. Create KV Namespaces

You need to create two KV namespaces:

1. One for storing credentials
2. One for storing login logs

Create them using the Cloudflare dashboard or Wrangler CLI:

```bash
wrangler kv:namespace create "CREDENTIALS"
wrangler kv:namespace create "LOG_KV"
```

### 2. Configure wrangler.toml

Create a `wrangler.toml` file in your project root with the following content:

```toml
name = "password-safe"
type = "javascript"
account_id = "your_account_id"
workers_dev = true
route = ""
zone_id = ""
compatibility_date = "2023-04-01"

# KV namespace for storing credentials
kv_namespaces = [
  { binding = "CREDENTIALS", id = "your_credentials_namespace_id" }
]

# KV namespace for storing login logs
kv_namespaces = [
  { binding = "LOG_KV", id = "your_logs_namespace_id" }
]
```

Replace `your_account_id`, `your_credentials_namespace_id`, and `your_logs_namespace_id` with actual values from your Cloudflare account.

### 3. Set Secrets

The application requires three secret values that should never be hardcoded:

- `ACCESS_PASSWORD`: The master password to access the application
- `JWT_SECRET`: Secret used to sign JWT tokens
- `SALT`: Salt used for encryption

Set these using Wrangler:

```bash
npx wrangler secret put ACCESS_PASSWORD
# Enter your master access password when prompted

npx wrangler secret put JWT_SECRET
# Enter a long random string for JWT signing

npx wrangler secret put SALT
# Enter a random string to use as encryption salt
```

### 4. Deploy the Application

Deploy your worker with:

```bash
npx wrangler deploy
```

## Configuration Details

### KV Namespaces

The application uses two separate KV namespaces:

1. `CREDENTIALS` - Stores the encrypted credentials
2. `LOG_KV` - Stores login attempt logs

Both namespaces must be configured in your `wrangler.toml` file with the correct IDs.

### Secrets Explained

- **ACCESS_PASSWORD**: This is the master password required to access the credential storage interface
- **JWT_SECRET**: Used to sign and verify JWT tokens for authentication
- **SALT**: Used in the encryption process for stored passwords

## Usage

After deployment, visit your worker's URL to access the application. You'll need to enter the `ACCESS_PASSWORD` to log in.

The interface allows you to:
- Add new credentials
- View existing credentials
- Update credentials
- Delete credentials
- View login history (last 10 attempts)

## Security Considerations

1. Always use strong, randomly generated values for secrets
2. Regularly rotate your secrets
3. Limit access to the worker URL
4. The application uses client-side encryption for passwords before storing in KV
5. All communication happens over HTTPS when deployed

## Troubleshooting

- If you can't access the application, verify your secrets are set correctly
- If credentials aren't saving, check KV namespace bindings
- Check the Cloudflare dashboard for worker execution errors
