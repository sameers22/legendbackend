const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); // ✅ for password hashing
const container = require('./cosmos');
const sendVerificationCode = require('./sendVerificationCode');
const { createCustomContainer } = require('./custom-cosmos');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SALT_ROUNDS = 10;

// 🔹 Test route
app.get('/api/test', (req, res) => {
  res.status(200).send("Server is working!");
});

// 🔹 Register route
app.post('/api/register', async (req, res) => {
  const { name, email, phone, birthday, password } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ message: "Name, email, and password are required." });
  }

  try {
    const existingUserQuery = {
      query: 'SELECT * FROM c WHERE c.email = @email',
      parameters: [{ name: '@email', value: email }]
    };
    const { resources: existingUsers } = await container.items.query(existingUserQuery).fetchAll();

    if (existingUsers.length > 0) {
      return res.status(409).json({ message: 'User already exists with this email.' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

    const newUser = {
      id: email,
      name,
      email,
      password: hashedPassword,
      verified: false,
      verificationCode,
      verificationExpires: Date.now() + 10 * 60 * 1000
    };

    if (phone) newUser.phone = phone;
    if (birthday) newUser.birthday = birthday;

    await container.items.create(newUser);
    await sendVerificationCode(email, verificationCode);

    res.status(201).json({ message: 'User registered. Check your email for the verification code.' });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: 'Error registering user', error: error.message });
  }
});

// 🔹 Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };

    const { resources } = await container.items.query(query).fetchAll();
    const user = resources[0];

    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    if (!user.verified) {
      return res.status(403).json({ message: 'Please verify your email before logging in.' });
    }

    res.status(200).json({ message: 'Login successful', user });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: 'Login error', error: error.message });
  }
});

// 🔹 Verify code route
app.post('/api/verify-code', async (req, res) => {
  const { email, code } = req.body;

  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };

    const { resources } = await container.items.query(query).fetchAll();
    const user = resources[0];

    if (!user) return res.status(400).json({ message: 'User not found.' });
    if (user.verified) return res.status(200).json({ message: 'Already verified.' });

    if (user.verificationCode === code && user.verificationExpires > Date.now()) {
      user.verified = true;
      delete user.verificationCode;
      delete user.verificationExpires;
      await container.item(user.id, user.id).replace(user);
      return res.status(200).json({ message: 'Email verified.' });
    } else {
      return res.status(400).json({ message: 'Invalid or expired code.' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Verification failed.', error: err.message });
  }
});

// 🔹 Forgot Password
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: 'Email is required.' });

  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };

    const { resources } = await container.items.query(query).fetchAll();
    const user = resources[0];

    if (!user) return res.status(404).json({ message: 'User not found.' });

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetCode = resetCode;
    user.resetExpires = Date.now() + 10 * 60 * 1000;

    await container.item(user.id, user.id).replace(user);
    await sendVerificationCode(email, resetCode);

    res.status(200).json({ message: 'Reset code sent to email.' });
  } catch (err) {
    console.error('Forgot password error:', err.message);
    res.status(500).json({ message: 'Failed to send reset code.' });
  }
});

// 🔹 Reset Password
app.post('/api/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;

  if (!email || !code || !newPassword) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };

    const { resources } = await container.items.query(query).fetchAll();
    const user = resources[0];

    if (!user || user.resetCode !== code || user.resetExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired reset code.' });
    }

    const samePassword = await bcrypt.compare(newPassword, user.password);
    if (samePassword) {
      return res.status(400).json({ message: 'New password cannot be the same as the old password.' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    user.password = hashedNewPassword;
    delete user.resetCode;
    delete user.resetExpires;

    await container.item(user.id, user.id).replace(user);
    res.status(200).json({ message: 'Password reset successfully.' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ message: 'Failed to reset password.' });
  }
});

// 🔹 Delete Account
app.delete('/api/delete-account', async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ message: 'Email is required.' });

  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };
    const { resources } = await container.items.query(query).fetchAll();
    const user = resources[0];

    if (!user) return res.status(404).json({ message: 'User not found.' });

    await container.item(user.id, user.id).delete();
    res.status(200).json({ message: 'Account deleted successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting account', error: err.message });
  }
});

// 🔹 Update User
app.put('/api/update-user', async (req, res) => {
  const { email, name, phone, birthday } = req.body;

  if (!email) return res.status(400).json({ message: 'Email is required to update user data.' });

  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };

    const { resources } = await container.items.query(query).fetchAll();
    const user = resources[0];

    if (!user) return res.status(404).json({ message: 'User not found.' });

    if (name) user.name = name;
    if (phone) user.phone = phone;
    if (birthday) user.birthday = birthday;

    await container.item(user.id, user.id).replace(user);
    res.status(200).json({ message: 'User updated successfully.', user });
  } catch (err) {
    res.status(500).json({ message: 'Error updating user', error: err.message });
  }
});

app.post("/api/custom-data", async (req, res) => {
  const { endpoint, key, databaseId, containerId } = req.body;

  if (!endpoint || !key || !databaseId || !containerId) {
    return res.status(400).json({ error: "Missing required fields." });
  }

  try {
    const container = createCustomContainer({ endpoint, key, databaseId, containerId });
    const { resources } = await container.items.query("SELECT * FROM c").fetchAll();

    res.json({ data: resources });
  } catch (err) {
    console.error("Custom DB fetch failed:", err.message);
    res.status(500).json({ error: "Could not fetch from provided Cosmos DB." });
  }
});

// 🔹 Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Backend listening on port ${PORT}`);
});
