require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { CosmosClient } = require('@azure/cosmos');
const sendVerificationCode = require('./sendVerificationCode');
const { createCustomContainer } = require('./custom-cosmos');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SALT_ROUNDS = 10;

// Cosmos DB setup
const client = new CosmosClient({
  endpoint: process.env.COSMOS_DB_ENDPOINT,
  key: process.env.COSMOS_DB_KEY,
});
const db = client.database(process.env.COSMOS_DB_DATABASE);
const container = db.container(process.env.COSMOS_DB_CONTAINER);

// 🔹 QR Project-specific Cosmos DB container
const qrClient = new CosmosClient({
  endpoint: process.env.COSMOS_DB_ENDPOINT,
  key: process.env.COSMOS_DB_KEY,
});
const qrDb = qrClient.database(process.env.COSMOS_DB_DATABASE2);
const qrContainer = qrDb.container(process.env.COSMOS_DB_CONTAINER2);


// ✅ Health Check
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', time: new Date().toISOString() });
});

// ========== AUTH ROUTES ==========

// ✅ Register
app.post('/api/register', async (req, res) => {
  const { name, email, phone, birthday, password } = req.body;
  if (!email || !password || !name) return res.status(400).json({ message: "Name, email, and password are required." });

  try {
    const existingUserQuery = {
      query: 'SELECT * FROM c WHERE c.email = @email',
      parameters: [{ name: '@email', value: email }]
    };
    const { resources: existingUsers } = await container.items.query(existingUserQuery).fetchAll();
    if (existingUsers.length > 0) return res.status(409).json({ message: 'User already exists.' });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

    const newUser = {
      id: email,
      name,
      email,
      password: hashedPassword,
      verified: false,
      verificationCode,
      verificationExpires: Date.now() + 10 * 60 * 1000,
      type: 'user',
    };
    if (phone) newUser.phone = phone;
    if (birthday) newUser.birthday = birthday;

    await container.items.create(newUser);
    await sendVerificationCode(email, verificationCode);
    res.status(201).json({ message: 'User registered. Check email for code.' });
  } catch (err) {
    res.status(500).json({ message: 'Registration error', error: err.message });
  }
});

// ✅ Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password required.' });

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
    if (!user.verified) return res.status(403).json({ message: 'Please verify your email.' });

    res.status(200).json({ message: 'Login successful', user });
  } catch (err) {
    res.status(500).json({ message: 'Login error', error: err.message });
  }
});

// ✅ Verify Code
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
    if (user.verificationCode === code && user.verificationExpires > Date.now()) {
      user.verified = true;
      delete user.verificationCode;
      delete user.verificationExpires;
      await container.item(user.id, user.id).replace(user);
      return res.status(200).json({ message: 'Email verified.' });
    }
    res.status(400).json({ message: 'Invalid or expired code.' });
  } catch (err) {
    res.status(500).json({ message: 'Verification failed.', error: err.message });
  }
});

// ✅ Forgot Password
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
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
    res.status(200).json({ message: 'Reset code sent.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to send reset code.' });
  }
});

// ✅ Reset Password
app.post('/api/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };
    const { resources } = await container.items.query(query).fetchAll();
    const user = resources[0];
    if (!user || user.resetCode !== code || user.resetExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired code.' });
    }

    const hashed = await bcrypt.hash(newPassword, SALT_ROUNDS);
    user.password = hashed;
    delete user.resetCode;
    delete user.resetExpires;

    await container.item(user.id, user.id).replace(user);
    res.status(200).json({ message: 'Password reset successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to reset password.' });
  }
});

// ✅ Delete Account
app.delete('/api/delete-account', async (req, res) => {
  const { email } = req.body;
  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.email = @e',
      parameters: [{ name: '@e', value: email }]
    };
    const { resources } = await container.items.query(query).fetchAll();
    const user = resources[0];
    if (!user) return res.status(404).json({ message: 'User not found.' });

    await container.item(user.id, user.id).delete();
    res.status(200).json({ message: 'Account deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Delete failed.', error: err.message });
  }
});

// ✅ Update User Info
app.put('/api/update-user', async (req, res) => {
  const { email, name, phone, birthday } = req.body;
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
    res.status(200).json({ message: 'User updated.', user });
  } catch (err) {
    res.status(500).json({ message: 'Update failed.', error: err.message });
  }
});

// ========== QR PROJECT ROUTES ==========

app.post('/api/save-project', async (req, res) => {
  const { name, text, time, qrImage, qrColor, bgColor } = req.body;

  if (!name || !text || !time) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    const newItem = {
      id: `${Date.now()}-${Math.random()}`,
      name,
      text,
      time,
      scanCount: 0,
      qrImage,
      qrColor: qrColor || '#000000',      // ✅ added
      bgColor: bgColor || '#ffffff',      // ✅ added
      type: 'qr_project',
    };

    const { resource } = await qrContainer.items.create(newItem);
    res.status(201).json({ message: 'Project saved', project: resource });
  } catch (err) {
    console.error('❌ Save Project Error:', err.message);
    res.status(500).json({ message: 'Save failed.', error: err.message });
  }
});


// ✅ Get All Projects
app.get('/api/get-projects', async (req, res) => {
  try {
    const query = {
      query: 'SELECT * FROM c WHERE c.type = @type ORDER BY c._ts DESC',
      parameters: [{ name: '@type', value: 'qr_project' }]
    };
    const { resources } = await qrContainer.items.query(query).fetchAll(); // 🔁 updated
    res.status(200).json({ projects: resources });
  } catch (err) {
    res.status(500).json({ message: 'Fetch failed.', error: err.message });
  }
});

// ✅ Get Single Project
app.get('/api/get-project/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { resource } = await qrContainer.item(id, id).read(); // 🔁 updated
    res.status(200).json({ project: resource });
  } catch (err) {
    res.status(404).json({ message: 'Project not found' });
  }
});

// ✅ Update Project
app.put('/api/update-project/:id', async (req, res) => {
  const { id } = req.params;
  const { name, text } = req.body;

  try {
    const { resource: existing } = await qrContainer.item(id, id).read(); // 🔁 updated
    const updated = {
      ...existing,
      name,
      text,
      time: new Date().toISOString(),
    };
    const { resource } = await qrContainer.items.upsert(updated); // 🔁 updated
    res.status(200).json({ message: 'Updated', project: resource });
  } catch (err) {
    res.status(500).json({ message: 'Update failed.', error: err.message });
  }
});

// ✅ Delete Project
app.delete('/api/delete-project/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await qrContainer.item(id, id).delete(); // 🔁 updated
    res.status(200).json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Delete failed.' });
  }
});

// ✅ Track Scans & Redirect
app.get('/track/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { resource: project } = await qrContainer.item(id, id).read(); // 🔁 updated
    if (!project || !project.text) return res.status(404).send('QR not found');
    project.scanCount = (project.scanCount || 0) + 1;
    await qrContainer.items.upsert(project); // 🔁 updated
    res.redirect(project.text.startsWith('http') ? project.text : `https://${project.text}`);
  } catch (err) {
    res.status(500).send('Tracking error');
  }
});

// ✅ Get Scan Count
app.get('/api/get-scan-count/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { resource: project } = await qrContainer.item(id, id).read(); // 🔁 updated
    res.status(200).json({ scanCount: project.scanCount || 0 });
  } catch (err) {
    res.status(500).json({ message: 'Scan count failed' });
  }
});

// ✅ Update QR Colors and (optionally) the QR Image
app.put('/api/update-color/:id', async (req, res) => {
  const { id } = req.params;
  const { qrColor, bgColor, qrImage } = req.body;

  if (!qrColor && !bgColor && !qrImage) {
    return res.status(400).json({ message: 'No update values provided' });
  }

  try {
    const { resource: existing } = await qrContainer.item(id, id).read();

    const updated = {
      ...existing,
      qrColor: qrColor ?? existing.qrColor,
      bgColor: bgColor ?? existing.bgColor,
      qrImage: qrImage ?? existing.qrImage, // ✅ Include updated image
      time: new Date().toISOString(),
    };

    const { resource } = await qrContainer.items.upsert(updated);
    res.status(200).json({ message: 'Colors and image updated', project: resource });
  } catch (err) {
    console.error('❌ Color/Image Update Error:', err.message);
    res.status(500).json({ message: 'Color/image update failed.', error: err.message });
  }
});

const fetch = require('node-fetch'); // At top of your backend if not already imported

app.get('/track/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    // New: Get city/country from IP
    let location = null;
    try {
      const locRes = await fetch(`http://ip-api.com/json/${ip}`);
      const locJson = await locRes.json();
      location = {
        city: locJson.city,
        region: locJson.regionName,
        country: locJson.country,
        lat: locJson.lat,
        lon: locJson.lon,
      };
    } catch (locErr) {
      // IP lookup failed; skip location
    }

    const { resource: project } = await qrContainer.item(id, id).read();
    if (!project || !project.text) return res.status(404).send('QR not found');
    project.scanCount = (project.scanCount || 0) + 1;
    project.scanEvents = project.scanEvents || [];
    project.scanEvents.push({
      timestamp: new Date().toISOString(),
      userAgent,
      ip,
      location, // <<------ ADD LOCATION!
    });
    await qrContainer.items.upsert(project);

    res.redirect(project.text.startsWith('http') ? project.text : `https://${project.text}`);
  } catch (err) {
    res.status(500).send('Tracking error');
  }
});


// ✅ Get Scan Analytics (history)
app.get('/api/get-scan-analytics/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { resource: project } = await qrContainer.item(id, id).read();
    if (!project) return res.status(404).json({ message: 'Project not found' });
    res.status(200).json({
      scanCount: project.scanCount || 0,
      scanEvents: project.scanEvents || [],
    });
  } catch (err) {
    res.status(500).json({ message: 'Scan analytics failed', error: err.message });
  }
});

// ========== CUSTOM COSMOS DB ROUTES ==========

// ✅ Custom Cosmos DB Viewer
app.post("/api/custom-data", async (req, res) => {
  const { endpoint, key, databaseId, containerId } = req.body;
  if (!endpoint || !key || !databaseId || !containerId)
    return res.status(400).json({ error: "Missing required fields." });

  try {
    const container = createCustomContainer({ endpoint, key, databaseId, containerId });
    const { resources } = await container.items.query("SELECT * FROM c").fetchAll();
    res.json({ data: resources });
  } catch (err) {
    res.status(500).json({ error: "Custom DB fetch failed." });
  }
});


// ✅ Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
