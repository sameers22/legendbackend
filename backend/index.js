const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const container = require('./cosmos');
const sendVerificationCode = require('./sendVerificationCode'); // ✅ updated to use code instead of link
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 🔹 Test route
app.get('/api/test', (req, res) => {
  res.status(200).send("Server is working!");
});

// 🔹 Register route (✅ phone & birthday optional)
app.post('/api/register', async (req, res) => {
  const { name, email, phone, birthday, password } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ message: "Name, email, and password are required." });
  }

  try {
    // Check if user exists
    const existingUserQuery = {
      query: 'SELECT * FROM c WHERE c.email = @email',
      parameters: [{ name: '@email', value: email }]
    };
    const { resources: existingUsers } = await container.items.query(existingUserQuery).fetchAll();

    if (existingUsers.length > 0) {
      return res.status(409).json({ message: 'User already exists with this email.' });
    }

    // Generate 6-digit verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Create new user object
    const newUser = {
      id: email,
      name,
      email,
      password,
      verified: false,
      verificationCode,
      verificationExpires: Date.now() + 10 * 60 * 1000 // 10 mins
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
    const querySpec = {
      query: "SELECT * FROM c WHERE c.email = @email AND c.password = @password",
      parameters: [
        { name: '@email', value: email },
        { name: '@password', value: password }
      ]
    };

    const { resources } = await container.items.query(querySpec).fetchAll();
    const user = resources[0];

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

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

// 🔹 Delete Account Route
app.delete('/api/delete-account', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required for account deletion.' });
  }

  try {
    // Fetch user
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };

    const { resources } = await container.items.query(query).fetchAll();

    if (resources.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = resources[0];

    // Delete user from Cosmos DB
    await container.item(user.id, user.id).delete();

    res.status(200).json({ message: 'Account deleted successfully.' });
  } catch (err) {
    console.error('Deletion error:', err.message);
    res.status(500).json({ message: 'Error deleting account', error: err.message });
  }
});

// 🔹 Update User Route
app.put('/api/update-user', async (req, res) => {
  const { email, name, phone, birthday } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required to update user data.' });
  }

  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };

    const { resources } = await container.items.query(query).fetchAll();
    const user = resources[0];

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (name) user.name = name;
    if (phone) user.phone = phone;
    if (birthday) user.birthday = birthday;

    await container.item(user.id, user.id).replace(user);

    res.status(200).json({ message: 'User updated successfully.', user });
  } catch (err) {
    console.error('Update error:', err.message);
    res.status(500).json({ message: 'Error updating user', error: err.message });
  }
});

// 🔹 Forgot Password: send reset code
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
    user.resetExpires = Date.now() + 10 * 60 * 1000; // 10 mins

    await container.item(user.id, user.id).replace(user);
    await sendVerificationCode(email, resetCode); // You can reuse the same function

    res.status(200).json({ message: 'Reset code sent to email.' });
  } catch (err) {
    console.error('Forgot password error:', err.message);
    res.status(500).json({ message: 'Failed to send reset code.' });
  }
});

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

    // ✅ Compare new password with old password
    if (user.password === newPassword) {
      return res.status(400).json({
        message: 'New password cannot be the same as the old password.',
      });
    }

    user.password = newPassword;
    delete user.resetCode;
    delete user.resetExpires;

    await container.item(user.id, user.id).replace(user);
    res.status(200).json({ message: 'Password reset successfully.' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ message: 'Failed to reset password.' });
  }
});



// 🔹 Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Backend listening on port ${PORT}`);
});
