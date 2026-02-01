// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const admin = require('firebase-admin');

const app = express();

// -------------------- Firebase Admin Init --------------------
// แก้ไข: ใช้ Environment Variables แทนการอ่านไฟล์ JSON เพื่อความปลอดภัยบน Vercel
const serviceAccount = {
  projectId: process.env.FIREBASE_PROJECT_ID,
  clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
  // จัดการเรื่องขึ้นบรรทัดใหม่ของ Private Key
  privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DB_URL
  });
}

const db = admin.database();

// -------------------- Middleware --------------------
app.use(cors());
app.use(express.json());

// -------------------- Helper --------------------
function isValidEmail(email) {
  return /\S+@\S+\.\S+/.test(email);
}

function isStrongPassword(password) {
  return typeof password === 'string' && password.length >= 6;
}

// -------------------- Routes --------------------

app.get('/', (req, res) => {
  res.send('PM Auth Backend is running on Vercel!');
});

// 1) สมัครสมาชิก
app.post('/api/register', async (req, res) => {
  try {
    const { firstName, lastName, gender, dateOfBirth, email, password } = req.body;

    if (!firstName || !lastName || !gender || !dateOfBirth || !email || !password) {
      return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบทุกช่อง' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'รูปแบบอีเมลไม่ถูกต้อง' });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({ message: 'รหัสผ่านควรมีอย่างน้อย 6 ตัวอักษร' });
    }

    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: `${firstName} ${lastName}`,
    });

    const uid = userRecord.uid;
    const now = new Date().toISOString();

    await db.ref(`users/${uid}`).set({
      firstName,
      lastName,
      gender,
      dateOfBirth,
      email,
      status: 'active',
      role: 'user',
      createdAt: now,
    });

    return res.status(201).json({
      message: 'สมัครสมาชิกสำเร็จ คุณสามารถเข้าสู่ระบบได้ทันที',
      uid,
    });
  } catch (err) {
    console.error('Register error:', err);
    if (err.code === 'auth/email-already-exists') {
      return res.status(400).json({ message: 'อีเมลนี้ถูกใช้สมัครแล้ว' });
    }
    return res.status(500).json({ message: 'เกิดข้อผิดพลาดจากเซิร์ฟเวอร์' });
  }
});

// 2) ล็อกอิน
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'กรุณากรอกอีเมลและรหัสผ่าน' });
    }

    const apiKey = process.env.FIREBASE_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ message: 'เซิร์ฟเวอร์ยังไม่ได้ตั้งค่า API Key' });
    }

    const signInUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`;
    const response = await axios.post(signInUrl, {
      email,
      password,
      returnSecureToken: true,
    });

    const { idToken, localId: uid } = response.data;
    const snapshot = await db.ref(`users/${uid}`).once('value');
    const profile = snapshot.val();

    if (!profile) {
      return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ใช้ในฐานข้อมูล' });
    }

    return res.json({
      message: 'เข้าสู่ระบบสำเร็จ',
      token: idToken,
      profile,
    });
  } catch (err) {
    console.error('Login error:', err?.response?.data || err);
    if (err.response && err.response.data && err.response.data.error) {
      const errorCode = err.response.data.error.message;
      if (errorCode === 'EMAIL_NOT_FOUND' || errorCode === 'INVALID_PASSWORD') {
        return res.status(400).json({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
      }
    }
    return res.status(500).json({ message: 'เกิดข้อผิดพลาดจากเซิร์ฟเวอร์' });
  }
});

// 3) ขอ reset password
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const apiKey = process.env.FIREBASE_API_KEY;
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`;

    await axios.post(url, {
      requestType: 'PASSWORD_RESET',
      email,
    });

    return res.json({
      message: 'ระบบได้ส่งอีเมลสำหรับตั้งรหัสผ่านใหม่ให้แล้ว (ถ้ามีอีเมลนี้ในระบบ)',
    });
  } catch (err) {
    return res.status(500).json({ message: 'เกิดข้อผิดพลาดจากเซิร์ฟเวอร์' });
  }
});

// สำคัญ: สำหรับ Vercel เราจะ export app แทนการใช้ app.listen
module.exports = app;