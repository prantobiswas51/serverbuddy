#!/usr/bin/env node
'use strict';
// Usage: node scripts/hash-password.js "my password"
// Prints the value to put in SB_PASSWORD_HASH.
const { hashPassword } = require('../src/auth');
const pw = process.argv[2];
if (!pw) {
  console.error('Usage: node scripts/hash-password.js "<password>"');
  process.exit(1);
}
console.log(hashPassword(pw));
