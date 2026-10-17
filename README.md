
# Secure Authentication API
### Week 7 – Day 1: Password Hashing Assignment

A Node.js and Express REST API demonstrating secure
password hashing, validated user registration, login
authentication, and brute-force attack prevention.

## Project Overview

This project demonstrates how bcrypt can protect user
passwords using hashing and salting. It also implements
secure authentication endpoints with input validation
and account lockout protection.

The application uses an in-memory users array for
storage and a JavaScript Map for tracking failed
login attempts.

## Project Objectives

1. Understand secure password hashing using bcrypt.
2. Demonstrate password salting and comparison.
3. Implement secure registration with validation.
4. Store password hashes instead of plain passwords.
5. Authenticate users with bcrypt.compare().
6. Prevent user enumeration during login.
7. Implement rate limiting to prevent brute-force attacks.
8. Apply a 15-minute lockout after five failed attempts.
9. Practice testing REST APIs using curl or Thunder Client.

## Technologies Used

- JavaScript (ES Modules)
- Node.js
- Express.js
- bcryptjs
- REST API
- VS Code
- Thunder Client / curl
- Git and GitHub

## Project Structure

week-7-day-1-assignment/
├── hash-demo.js
├── server.js
├── package.json
├── package-lock.json
├── .gitignore
└── README.md

## Live Pages
[https://dominic-kores.github.io/password-hashing/]

## Installation and Setup

### 1. Clone the repository

    git clone <https://github.com/Dominic-kores/password-hashing>
    cd week-7-day-1-assignment

### 2. Install dependencies

    npm install

### 3. Run the hashing demonstration

    npm run hash

### 4. Start the development server

    npm run dev

### 5. Open the API

    http://localhost:3000

The server runs on port 3000 by default.

## Task 1: Password Hashing

File: `hash-demo.js`

The hashing script demonstrates:

- Hashing five passwords using bcrypt with cost factor 10.
- Generating unique hashes for the same password.
- Verifying valid passwords with bcrypt.compare().
- Rejecting incorrect passwords.

### Run

    npm run hash

Expected results:

- Different hashes for identical passwords: true
- Correct password comparison: true
- Incorrect password comparison: false

## Task 2: Secure User Registration

Endpoint:

    POST /api/auth/register

Example request:

    {
      "name": "Jane Wanjiku",
      "email": "wanjiku@mail.com",
      "password": "Secure123!"
    }

Validation requirements:

- Valid email address.
- Password with at least eight characters.
- Password includes one uppercase letter and one number.
- Name contains at least two characters after trimming.
- Duplicate emails are rejected case-insensitively.
- Passwords are hashed before being stored.

Successful response: HTTP 201

    {
      "user": {
        "id": 1,
        "email": "wanjiku@mail.com",
        "name": "Jane Wanjiku"
      },
      "message": "User registered successfully."
    }

## Task 3: Login with Rate Limiting

Endpoint:

    POST /api/auth/login

Example request:

    {
      "email": "wanjiku@mail.com",
      "password": "Secure123!"
    }

Features:

- Password verification with bcrypt.compare().
- Case-insensitive email matching.
- Generic error messages for invalid credentials.
- Failed-attempt tracking with a JavaScript Map.
- Maximum of five failed attempts.
- Account lockout for 15 minutes.
- HTTP 429 for requests during lockout.
- Automatic counter reset after successful login.
- Remaining lockout time included in error responses.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | / | Server status |
| POST | /api/auth/register | Register user |
| POST | /api/auth/login | Authenticate user |

## HTTP Status Codes

| Status | Meaning |
|--------|---------|
| 200 | Login successful |
| 201 | Registration successful |
| 400 | Input validation error |
| 401 | Invalid login credentials |
| 404 | Route not found |
| 409 | Duplicate email |
| 429 | Account temporarily locked |
| 500 | Internal server error |

## Testing

The API was designed to be tested using
Thunder Client, Postman or curl.

Recommended test cases:

1. Register a valid user.
2. Attempt registration with an existing email.
3. Submit a weak password.
4. Submit an invalid email address.
5. Log in with correct credentials.
6. Log in with incorrect credentials.
7. Attempt login using an unknown email.
8. Submit five consecutive failed logins.
9. Verify that the sixth attempt returns 429.
10. Verify that lockout expires after 15 minutes.
11. Confirm successful login clears failed attempts.
12. Verify that password hashes are never returned.

## Security Considerations

- Passwords are hashed using bcrypt.
- bcrypt generates a random salt for each hash.
- Password hashes are not exposed in API responses.
- Passwords are compared using bcrypt.compare().
- Input validation rejects invalid registration data.
- Generic authentication errors reduce user enumeration.
- Rate limiting reduces repeated guessing attempts.


## Key Learning Outcomes

This assignment strengthened my understanding of
authentication security, password hashing, input
validation, HTTP responses and brute-force protection.

It also provided hands-on experience developing and
testing REST API endpoints using Node.js and Express.






## Author

**Dominic Kores Kisioya**

Full-Stack Software & AI Engineer

