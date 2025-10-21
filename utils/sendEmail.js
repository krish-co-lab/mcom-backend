import nodemailer from "nodemailer";

const sendEmail = async ({ email, subject, message }) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      service: process.env.SMTP_SERVICE,
      auth: {
        user: process.env.SMTP_MAIL,
        pass: process.env.SMTP_PASSWORD,
      },
    });

    await transporter.sendMail({
      from: process.env.SMTP_MAIL,
      to: email,
      subject,
      html: message,
    });

    console.log("✅ Email sent successfully");
  } catch (error) {
    console.log("❌ Email not sent:", error.message);
  }
};

export default sendEmail;
