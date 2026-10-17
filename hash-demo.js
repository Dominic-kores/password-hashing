
import bcrypt from "bcryptjs";

// ======================================================
// TASK 1: PASSWORD HASHING AND COMPARISON
// ======================================================

// Cost factor determines how computationally expensive
// password hashing will be.
const SALT_ROUNDS = 10;

// The five passwords provided in the assignment.
const passwords = [
  "Nairobi2026!",
  "securePass123",
  "myS3cretK3y",
  "W@njiku#Strong",
  "simple",
];

// ------------------------------------------------------
// FUNCTION: Demonstrate password hashing with bcrypt
// ------------------------------------------------------
async function demonstrateHashing() {
  try {
    console.log("\n==================================");
    console.log("   BCRYPT PASSWORD HASHING DEMO");
    console.log("==================================\n");

    // Store generated hashes for later verification.
    const hashedPasswords = [];

    // STEP 1: Hash each password.
    console.log("STEP 1: HASHING FIVE PASSWORDS\n");

    for (const password of passwords) {
      // bcrypt automatically generates a random salt.
      const hash = await bcrypt.hash(
        password,
        SALT_ROUNDS
      );

      hashedPasswords.push({
        password,
        hash,
      });

      // Printing passwords is for this educational
      // demonstration only, not for production logging.
      console.log(`Password: "${password}"`);
      console.log(`Hash: ${hash}\n`);
    }

    // STEP 2: Hash the same password twice.
    console.log("----------------------------------");
    console.log("STEP 2: HASHING THE SAME PASSWORD TWICE\n");

    const examplePassword = "Nairobi2026!";

    const hash1 = await bcrypt.hash(
      examplePassword,
      SALT_ROUNDS
    );

    const hash2 = await bcrypt.hash(
      examplePassword,
      SALT_ROUNDS
    );

    console.log(`Original: "${examplePassword}"`);
    console.log(`Hash 1: ${hash1}`);
    console.log(`Hash 2: ${hash2}`);
    console.log(`Hashes are different: ${hash1 !== hash2}`);

    // STEP 3: Verify each correct password.
    console.log("\n----------------------------------");
    console.log("STEP 3: VERIFYING CORRECT PASSWORDS\n");

    for (const item of hashedPasswords) {
      // compare() checks a plain-text password
      // against its corresponding stored hash.
      const isMatch = await bcrypt.compare(
        item.password,
        item.hash
      );

      console.log(
        `"${item.password}" verification: ${isMatch}`
      );
    }

    // STEP 4: Test an incorrect password
    // against every generated hash.
    console.log("\n----------------------------------");
    console.log("STEP 4: TESTING INCORRECT PASSWORD\n");

    for (const item of hashedPasswords) {
      const isMatch = await bcrypt.compare(
        "WrongPassword",
        item.hash
      );

      console.log(
        `"WrongPassword" vs "${item.password}": ${isMatch}`
      );
    }

    // Also verify the two independently salted hashes.
    const firstMatch = await bcrypt.compare(
      examplePassword,
      hash1
    );

    const secondMatch = await bcrypt.compare(
      examplePassword,
      hash2
    );

    console.log("\nSTEP 5: VERIFYING BOTH SALTED HASHES");
    console.log(`Hash 1 verification: ${firstMatch}`);
    console.log(`Hash 2 verification: ${secondMatch}`);

    console.log("\nHashing demonstration completed!\n");

  } catch (error) {
    console.error(
      "Password hashing demonstration failed:",
      error.message
    );

    process.exitCode = 1;
  }
}

// Execute the demonstration.
demonstrateHashing();
