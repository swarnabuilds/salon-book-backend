# SalonBook — Server

Express REST API for SalonBook. It owns services, appointments, customers, and payment transactions. Authentication is handled by Better Auth in the Next.js client; this API verifies sessions and signed JWTs using the shared `BETTER_AUTH_SECRET`.

## Important Features

- Public service listing with search, category filtering, and active-only rules
- Admin-only service create, update, delete, and activate/deactivate operations
- Appointment creation, listing, detail lookup, confirmation, and cancellation
- Customer-scoped appointment access and admin-wide appointment management
- Blocked-user enforcement on protected endpoints
- Admin customer management (list, search, block, unblock)
- Read-only transaction ledger
- Payment status updates only through the verified Stripe flow in the client
- JWT verification middleware plus Better Auth session introspection
- Role checks performed on the server for every protected API

## Technology Stack

- Node.js
- Express.js
- MongoDB
- CORS
- dotenv
- Native Node `crypto` for HS256 JWT verification

## Installation

```bash
git clone https://github.com/swarnabuilds/salon-book-backend.git
cd salon-book-backend
npm install
```

## Run Locally

Create a `.env` file using the variable names below, then run:

```bash
npm run dev
```

The API listens on `http://localhost:5000` by default. For a production-style run:

```bash
npm start
```

## Required Environment Variables

Names only — never commit actual values.

- `MONGO_URI`
- `PORT`
- `BETTER_AUTH_SECRET`
- `CLIENT_URL`
- `BETTER_AUTH_URL`

`BETTER_AUTH_SECRET` must exactly match the value in the client application. `CLIENT_URL` is the deployed Next.js origin and is used for CORS and session verification.

## Live Website Link

Add the deployed client URL here before submission: `https://<your-deployed-salonbook-domain>`

## Repository Links

- Client: https://github.com/swarnabuilds/salon-book-frontend.git
- Server: https://github.com/swarnabuilds/salon-book-backend.git

## Deployment Guideline

- Deploy this Node service with all environment variables configured by the hosting provider.
- Set `CLIENT_URL` and `BETTER_AUTH_URL` to the deployed Next.js origin.
- Add the deployed client origin to the CORS allowlist (comma-separated values are supported).
- Keep `.env` files and secrets out of GitHub.
- Confirm there are no CORS, 404, or 504 errors and that private routes still work after page refresh.
- Verify admin and customer role permissions with separate accounts before submission.
