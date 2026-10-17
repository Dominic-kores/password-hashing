
import express from "express";
import bcrypt from "bcryptjs";

// ======================================================
// WEEK 7 - DAY 1: PASSWORD HASHING ASSIGNMENT
// Tasks 2 and 3: Registration and Secure Login
// ======================================================

// Initialize the Express application.
const app = express();

// Server configuration.
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// Brute-force protection settings.
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes

// Express middleware to parse incoming JSON requests.
app.use(express.json());

// ======================================================
// SECTION 1: IN-MEMORY DATA STORAGE
// ======================================================

// Users will be stored in this array.
// Data will be lost when the server restarts.
const users = [];

// Generate unique numeric IDs for each registered user.
let nextUserId = 1;

// Map structure:
// email => { count: number, lockedUntil: Date | null }
//
// Tracks failed login attempts for each email.
const loginAttempts = new Map();

// ======================================================
// SECTION 2: HELPER FUNCTIONS
// ======================================================

// Normalize an email to make matching case-insensitive.
function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

// Check whether an email has a valid basic format.
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Check whether a password meets assignment rules.
// Minimum 8 characters, 1 uppercase letter and 1 number.
function isValidPassword(password) {
  return (
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password)
  );
}

// Return a public user object without the password hash.
// This prevents sensitive data from being sent in JSON.
function getPublicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
  };
}

// Standardized lockout response with minutes remaining.
function sendLockResponse(res, lockedUntil) {
  const remainingMs = Math.max(
    0,
    lockedUntil - Date.now()
  );

  const remainingMinutes = Math.ceil(
    remainingMs / (60 * 1000)
  );

  return res.status(429).json({
    error: `Account locked. Try again in ${remainingMinutes} minutes.`,
  });
}

// ======================================================
// SECTION 3: HOME ROUTE
// ======================================================

// Used to confirm that the server is working.
app.get("/", (req, res) => {
  return res.status(200).json({
    message: "Password Hashing API is running",
    endpoints: {
      register: "POST /api/auth/register",
      login: "POST /api/auth/login",
    },
  });
});

// ======================================================
// SECTION 4: TASK 2 - SECURE USER REGISTRATION
// ======================================================

app.post("/api/auth/register", async (req, res) => {
  try {
    // Read registration data from the JSON body.
    const { email, password, name } = req.body ?? {};

    // STEP 1: Check required field types.
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      typeof name !== "string"
    ) {
      return res.status(400).json({
        error: "Name, email and password are required.",
      });
    }

    // STEP 2: Normalize name and email.
    const cleanName = name.trim();
    const cleanEmail = normalizeEmail(email);

    // STEP 3: Validate the name.
    if (cleanName.length < 2) {
      return res.status(400).json({
        error: "Name must contain at least 2 characters.",
      });
    }

    // STEP 4: Validate the email address.
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({
        error: "Please provide a valid email address.",
      });
    }

    // STEP 5: Validate password strength.
    if (!isValidPassword(password)) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters long and contain an uppercase letter and a number.",
      });
    }

    // STEP 6: Check for an existing email.
    // Both uppercase and lowercase variations are rejected.
    const existingUser = users.find(
      (user) => user.email === cleanEmail
    );

    if (existingUser) {
      return res.status(409).json({
        error: "Email already registered.",
      });
    }

    // STEP 7: Hash the password securely.
    const passwordHash = await bcrypt.hash(
      password,
      SALT_ROUNDS
    );

    // STEP 8: Create the new user object.
    const newUser = {
      id: nextUserId++,
      name: cleanName,
      email: cleanEmail,
      passwordHash,
    };

    // STEP 9: Save the user in memory.
    users.push(newUser);

    // STEP 10: Return a safe response.
    // Never return passwordHash to the client.
    return res.status(201).json({
      user: getPublicUser(newUser),
      message: "User registered successfully.",
    });
  } catch (error) {
    console.error("Registration error:", error);

    return res.status(500).json({
      error: "Internal server error.",
    });
  }
});

// ======================================================
// SECTION 5: TASK 3 - LOGIN WITH RATE LIMITING
// ======================================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body ?? {};

    // STEP 1: Validate input types.
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: "Email and password are required.",
      });
    }

    // STEP 2: Normalize email.
    const cleanEmail = normalizeEmail(email);

    // STEP 3: Retrieve the failed-attempt record.
    let attempt = loginAttempts.get(cleanEmail) || {
      count: 0,
      lockedUntil: null,
    };

    // STEP 4: Check for an active lockout.
    if (attempt.lockedUntil) {
      if (Date.now() < attempt.lockedUntil) {
        return sendLockResponse(
          res,
          attempt.lockedUntil
        );
      }

      // Lockout has expired; allow a fresh set of attempts.
      loginAttempts.delete(cleanEmail);

      attempt = {
        count: 0,
        lockedUntil: null,
      };
    }

    // STEP 5: Search for a user by email.
    const user = users.find(
      (item) => item.email === cleanEmail
    );

    // STEP 6: Compare the submitted password.
    // For unknown users, compare against a dummy hash
    // to reduce timing differences between outcomes.
    const dummyHash =
      "$2b$10$C6UzMDM.H6dfI/f/IKcEeOZfK7xP7hQhM" +
      "DAn0EFM1SFM1kl.x5VGO";

    const hashToCompare = user
      ? user.passwordHash
      : dummyHash;

    const passwordMatches = await bcrypt.compare(
      password,
      hashToCompare
    );

    // STEP 7: Handle invalid credentials.
    if (!user || !passwordMatches) {
      attempt.count += 1;

      // Once the 5th attempt fails, start a lockout.
      if (attempt.count >= MAX_FAILED_ATTEMPTS) {
        attempt.lockedUntil = Date.now() + LOCK_TIME;
      }

      // Save the updated failed-attempt record.
      loginAttempts.set(cleanEmail, attempt);

      // Use the SAME message for an unknown user
      // and for an incorrect password.
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    // STEP 8: Successful login.
    // Reset any previous failed-attempt counter.
    loginAttempts.delete(cleanEmail);

    // STEP 9: Return the authenticated user.
    // No password or password hash is exposed.
    return res.status(200).json({
      message: "Login successful",
      user: getPublicUser(user),
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      error: "Internal server error.",
    });
  }
});

// ======================================================
// SECTION 6: FALLBACK ROUTE
// ======================================================

// Respond to unsupported API routes with HTTP 404.
app.use((req, res) => {
  return res.status(404).json({
    error: "Route not found.",
  });
});

// ======================================================
// SECTION 7: START THE SERVER
// ======================================================

app.listen(PORT, () => {
  console.log("===================================");
  console.log(" PASSWORD HASHING AUTH API");
  console.log("===================================");
  console.log(`Server running on http://localhost:${PORT}`);
  console.log("POST /api/auth/register");
  console.log("POST /api/auth/login");
  console.log("===================================");
});
