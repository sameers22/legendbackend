// sendVerificationCode.js

const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // your Gmail address
    pass: process.env.EMAIL_PASS  // your Gmail app password
  }
});

module.exports = async function sendVerificationCode(email, code) {
  const mailOptions = {
    from: `"Legend Cookhouse" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify Your Email - Legend Cookhouse',
    text: `Your 6-digit verification code is: ${code}\n\nThis code will expire in 10 minutes.`
  };

  await transporter.sendMail(mailOptions);
};
