const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

async function sendVerificationEmail(email, code) {
    try {
        const info = await transporter.sendMail({
        from: `"JMCoin" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Verify Your Email',
        html: `<h3>Your verification code is: ${code}</h3>`
        });

        console.log('✅ Verification email sent to:', email);
        console.log('Message ID:', info.messageId);
    } catch (err) {
        console.error('❌ Failed to send verification email:', err.message);
        throw new Error('Email sending failed');
    }
}

module.exports = sendVerificationEmail;
