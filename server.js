// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 4000;

// -------------------- Firebase Admin Init --------------------
const serviceAccount = require("./firebase-service-account.json"); // 👈 ชื่อไฟล์ key

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DB_URL
});

const db = admin.database();

// -------------------- Middleware --------------------
app.use(cors());
app.use(express.json()); // รองรับ JSON body

// -------------------- Helper --------------------
function isValidEmail(email) {
  return /\S+@\S+\.\S+/.test(email);
}

function isStrongPassword(password) {
  // แค่ตัวอย่างง่าย ๆ: อย่างน้อย 6 ตัว
  return typeof password === 'string' && password.length >= 6;
}

// -------------------- Routes --------------------

// 1) สมัครสมาชิก
// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      gender,
      dateOfBirth,
      email,
      password,
    } = req.body;

    // ----- ตรวจสอบข้อมูลเบื้องต้น -----
    if (!firstName || !lastName || !gender || !dateOfBirth || !email || !password) {
      return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบทุกช่อง' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'รูปแบบอีเมลไม่ถูกต้อง' });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({ message: 'รหัสผ่านควรมีอย่างน้อย 6 ตัวอักษร' });
    }

    // ----- สร้าง user ใน Firebase Authentication -----
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: `${firstName} ${lastName}`,
    });

    const uid = userRecord.uid;

    // ----- บันทึกโปรไฟล์ลง Realtime Database -----
    const now = new Date().toISOString();

    await db.ref(`users/${uid}`).set({
      firstName,
      lastName,
      gender,
      dateOfBirth,
      email,
      // 🔁 เปลี่ยนจาก pending -> active (หรือจะไม่ใช้ field นี้ก็ได้)
      status: 'active',
      role: 'user',
      createdAt: now,
    });

    return res.status(201).json({
      // 🔁 เปลี่ยนข้อความเป็นใช้งานได้เลย
      message: 'สมัครสมาชิกสำเร็จ คุณสามารถเข้าสู่ระบบได้ทันที',
      uid,
    });
  } catch (err) {
    console.error('Register error:', err);

    // ถ้า email ซ้ำ
    if (err.code === 'auth/email-already-exists') {
      return res.status(400).json({ message: 'อีเมลนี้ถูกใช้สมัครแล้ว' });
    }

    return res.status(500).json({ message: 'เกิดข้อผิดพลาดจากเซิร์ฟเวอร์' });
  }
});

// 2) ล็อกอิน
// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'กรุณากรอกอีเมลและรหัสผ่าน' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'รูปแบบอีเมลไม่ถูกต้อง' });
    }

    const apiKey = process.env.FIREBASE_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ message: 'ยังไม่ได้ตั้งค่า FIREBASE_API_KEY ใน .env' });
    }

    // ----- ใช้ Firebase Auth REST API เช็ค email/password -----
    const signInUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`;

    const response = await axios.post(signInUrl, {
      email,
      password,
      returnSecureToken: true,
    });

    const { idToken, localId: uid } = response.data;

    // ----- อ่านโปรไฟล์จาก Realtime Database -----
    const snapshot = await db.ref(`users/${uid}`).once('value');
    const profile = snapshot.val();

    if (!profile) {
      return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ใช้ในฐานข้อมูล' });
    }

    // ❌ ลบส่วนเช็ค pending / declined ออก
    // if (profile.status === 'pending') {
    //   return res.status(403).json({ message: 'บัญชีของคุณกำลังรอการอนุมัติจากผู้ดูแลระบบ' });
    // }
    // if (profile.status === 'declined') {
    //   return res.status(403).json({ message: 'บัญชีของคุณไม่ได้รับอนุมัติการเข้าใช้งาน' });
    // }

    // ----- ล็อกอินสำเร็จ -----
    return res.json({
      message: 'เข้าสู่ระบบสำเร็จ',
      token: idToken, // token นี้ใช้เรียก API อื่นต่อได้ถ้าต้องการ
      profile,
    });
  } catch (err) {
    console.error('Login error:', err?.response?.data || err);

    // error จาก Firebase Auth REST
    if (err.response && err.response.data && err.response.data.error) {
      const errorCode = err.response.data.error.message;

      if (errorCode === 'EMAIL_NOT_FOUND' || errorCode === 'INVALID_PASSWORD') {
        return res.status(400).json({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
      }

      if (errorCode === 'USER_DISABLED') {
        return res.status(403).json({ message: 'บัญชีนี้ถูกปิดการใช้งาน' });
      }
    }

    return res.status(500).json({ message: 'เกิดข้อผิดพลาดจากเซิร์ฟเวอร์' });
  }
});

// 3) ขอ reset password
// POST /api/forgot-password
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'กรุณากรอกอีเมล' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'รูปแบบอีเมลไม่ถูกต้อง' });
    }

    const apiKey = process.env.FIREBASE_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ message: 'ยังไม่ได้ตั้งค่า FIREBASE_API_KEY ใน .env' });
    }

    const url = `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`;

    await axios.post(url, {
      requestType: 'PASSWORD_RESET',
      email,
    });

    return res.json({
      message: 'ระบบได้ส่งอีเมลสำหรับตั้งรหัสผ่านใหม่ให้แล้ว (ถ้ามีอีเมลนี้ในระบบ)',
    });
  } catch (err) {
    console.error('Forgot password error:', err?.response?.data || err);

    return res.status(500).json({ message: 'เกิดข้อผิดพลาดจากเซิร์ฟเวอร์' });
  }
});

// -------------------- Start Server --------------------
app.get('/', (req, res) => {
  res.send('PM Auth Backend is running...');
});

app.listen(PORT, () => {
  console.log(`✅ Server is running on http://localhost:${PORT}`);
});
