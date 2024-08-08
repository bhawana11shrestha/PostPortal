require('dotenv').config(); // Load environment variables
const express = require('express');
const axios = require('axios');
const crypto = require('crypto'); // Cryptographic library
const cors = require('cors'); // Import CORS middleware
const session = require('express-session'); // Import express-session for managing sessions
const Canva = require('../models/Canva'); // Import the Canva model
const User = require('../models/User');
const { getSessionById } = require('../utils/session');
const { clearScreenDown } = require('readline');


const router = express.Router();
router.use(cors());



// Mock function to simulate fetching the client from your database or configuration
function getClient() {
  return {
    clientId: process.env.CANVA_CLIENT_ID,
    clientSecret: process.env.CANVA_CLIENT_SECRET,
    redirectUri: 'https://4c2a-110-44-121-117.ngrok-free.app/canva/callback',
  };
}

function generateCodeVerifierAndChallenge() {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = crypto.randomBytes(32).toString("base64url");
  return { codeVerifier, codeChallenge, state };
}

// Start OAuth Flow
router.get('/initiate_oauth', async (req, res) => {
  const userId = req.query.userId;
  if (!userId) {
    return res.status(400).send('Invalid request: userId is required');
  }
  
  const client = getClient();
  const { codeVerifier, codeChallenge, state } = generateCodeVerifierAndChallenge();

  req.session.codeVerifier = codeVerifier;
  req.session.state = state;
  req.session.userId = userId;
  console.log('Session ID:', req.sessionID);

  req.session.save((err) => {
    if (err) {
      console.error('Session save error:', err);
      return res.status(500).send('Session save error');
    }
    console.log('Session saved successfully');

    const authUrl = `https://www.canva.com/api/oauth/authorize?code_challenge=${codeChallenge}&code_challenge_method=s256&scope=design:content:read%20design:content:write%20design:meta:read%20folder:read%20folder:write&response_type=code&client_id=${client.clientId}&state=${state}&redirect_uri=${encodeURIComponent(client.redirectUri)}`;

    res.json({ authUrl, sessionId: req.sessionID });
  });
});

router.get('/callback', async (req, res) => {
  const { code, state, sessionId } = req.query;

  // Check if required parameters are present
  if (!code || !state || !sessionId) {
    console.error('Missing required parameters');
    return res.status(400).send('Missing required parameters');
  }

  // Retrieve session by sessionId
  const session = await getSessionById(sessionId);
  if (!session) {
    console.error('Session not found:', sessionId);
    return res.status(400).send('Session not found');
  }

  const storedCodeVerifier = session.codeVerifier;
  const storedState = session.state;

  // Validate state and code verifier
  if (state !== storedState) {
    console.error('State mismatch detected. Expected:', storedState, 'Received:', state);
    return res.status(403).send('State mismatch');
  }

  if (!storedCodeVerifier) {
    console.error('Code verifier not found in session');
    return res.status(400).send('Code verifier not found in session');
  }

  const client = getClient();

  try {
    const credentials = Buffer.from(`${client.clientId}:${client.clientSecret}`).toString('base64');

    const bodyParams = new URLSearchParams();
    bodyParams.append('grant_type', 'authorization_code');
    bodyParams.append('code_verifier', storedCodeVerifier);
    bodyParams.append('code', code);
    bodyParams.append('redirect_uri', client.redirectUri);

    const response = await axios.post('https://api.canva.com/rest/v1/oauth/token', bodyParams.toString(), {
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const { access_token, expires_in, refresh_token } = response.data;

    const user = await User.findById(session.userId);
    if (!user) {
      console.error('User not found:', session.userId);
      return res.status(404).send('User not found');
    }

    const canva = new Canva({
      accessToken: access_token,
      refreshToken: refresh_token,
      userId: session.userId,
      expiresAt: Date.now() + expires_in * 1000,
    });
    await canva.save();

    res.json({ accessToken: access_token, refreshToken: refresh_token });

  } catch (error) {
    console.error('Error exchanging code for access token:', error.response ? error.response.data : error.message);
    res.status(500).send('Failed to obtain access token');
  }
});



module.exports = router;
