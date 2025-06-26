const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

async function sendVerificationEmail(email, code) {
    await transporter.sendMail({
        from: `"JMCoin" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Verify Your Email',
        html: `<h3>Your verification code is: ${code}</h3>`
    });
}

module.exports = sendVerificationEmail;
