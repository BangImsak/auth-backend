// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 4000;

// -------------------- Firebase Admin Init --------------------
const serviceAccount = require('./firebase-service-account.json'); // 👈 ชื่อไฟล์ key

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DB_URL,
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
  // ตัวอย่างง่าย ๆ: อย่างน้อย 6 ตัว
  return typeof password === 'string' && password.length >= 6;
}

// -------------------- Routes --------------------

// 1) สมัครสมาชิก (ต้องไปยืนยันอีเมลก่อนถึงจะใช้งานได้)
app.post('/api/register', async (req, res) => {
  try {
    const { firstName, lastName, gender, dateOfBirth, email, password } = req.body;

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
    const now = new Date().toISOString();

    // ----- บันทึกโปรไฟล์ลง Realtime Database -----
    await db.ref(`users/${uid}`).set({
      firstName,
      lastName,
      gender,
      dateOfBirth,
      email,
      status: 'pending',        // ✅ ยัง "สมัครไม่สมบูรณ์" จนกว่าจะยืนยันอีเมล
      role: 'user',
      emailVerified: false,
      createdAt: now,
    });

    // ----- ส่งอีเมลยืนยัน -----
    const apiKey = process.env.FIREBASE_API_KEY;
    if (!apiKey) {
      console.error('FIREBASE_API_KEY is missing in .env');
      return res.status(201).json({
        message:
          'สมัครเกือบสำเร็จแล้ว แต่ยังไม่ได้ส่งอีเมลยืนยัน เนื่องจากยังไม่ได้ตั้งค่า FIREBASE_API_KEY',
        uid,
      });
    }

    // 1) sign-in เพื่อขอ idToken (ใช้ email/password ที่เพิ่งสมัคร)
    const signInUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`;

    const signInRes = await axios.post(signInUrl, {
      email,
      password,
      returnSecureToken: true,
    });

    const idToken = signInRes.data.idToken;

    // 2) เรียก sendOobCode แบบ VERIFY_EMAIL
    const sendOobUrl = `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`;

    await axios.post(sendOobUrl, {
      requestType: 'VERIFY_EMAIL',
      idToken,
    });

    return res.status(201).json({
      message:
        'สมัครเกือบสำเร็จแล้ว! ระบบได้ส่งอีเมลให้คุณยืนยันแล้ว กรุณาคลิกปุ่มยืนยันในอีเมลเพื่อเปิดใช้งานบัญชี',
      uid,
    });
  } catch (err) {
    console.error('Register error:', err?.response?.data || err);

    if (err.code === 'auth/email-already-exists') {
      return res.status(400).json({ message: 'อีเมลนี้ถูกใช้สมัครแล้ว' });
    }

    return res.status(500).json({ message: 'เกิดข้อผิดพลาดจากเซิร์ฟเวอร์' });
  }
});

// 2) ล็อกอิน (อนุญาตเฉพาะผู้ที่ยืนยันอีเมลแล้วเท่านั้น)
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
      return res
        .status(500)
        .json({ message: 'ยังไม่ได้ตั้งค่า FIREBASE_API_KEY ใน .env' });
    }

    // ----- ใช้ Firebase Auth REST API เช็ค email/password -----
    const signInUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`;

    const response = await axios.post(signInUrl, {
      email,
      password,
      returnSecureToken: true,
    });

    const { idToken, localId: uid } = response.data;

    // ----- ดึงข้อมูลบัญชีเพื่อตรวจว่า emailVerified หรือยัง -----
    const lookupUrl = `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`;

    const accountInfoRes = await axios.post(lookupUrl, { idToken });
    const userInfo = accountInfoRes.data.users && accountInfoRes.data.users[0];
    const emailVerified = userInfo?.emailVerified || false;

    if (!emailVerified) {
      // ยังไม่ยืนยันอีเมล → ห้ามเข้า
      return res.status(403).json({
        message:
          'บัญชียังไม่ได้ยืนยันอีเมล กรุณาเปิดกล่องจดหมายและคลิกปุ่มยืนยันในอีเมลก่อนเข้าสู่ระบบ',
      });
    }

    // ----- อ่านโปรไฟล์จาก Realtime Database -----
    const snapshot = await db.ref(`users/${uid}`).once('value');
    const profile = snapshot.val();

    if (!profile) {
      return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ใช้ในฐานข้อมูล' });
    }

    // ถ้าใน DB ยังเป็น pending แต่ emailVerified แล้ว → อัพเดตเป็น active
    if (profile.status === 'pending') {
      await db.ref(`users/${uid}`).update({
        status: 'active',
        emailVerified: true,
      });
      profile.status = 'active';
      profile.emailVerified = true;
    }

    // ----- ล็อกอินสำเร็จ -----
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

      if (errorCode === 'USER_DISABLED') {
        return res.status(403).json({ message: 'บัญชีนี้ถูกปิดการใช้งาน' });
      }
    }

    return res.status(500).json({ message: 'เกิดข้อผิดพลาดจากเซิร์ฟเวอร์' });
  }
});

// 3) ขอ reset password
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
      return res
        .status(500)
        .json({ message: 'ยังไม่ได้ตั้งค่า FIREBASE_API_KEY ใน .env' });
    }

    const url = `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`;

    await axios.post(url, {
      requestType: 'PASSWORD_RESET',
      email,
    });

    return res.json({
      message:
        'ระบบได้ส่งอีเมลสำหรับตั้งรหัสผ่านใหม่ให้แล้ว (ถ้ามีอีเมลนี้ในระบบ)',
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
