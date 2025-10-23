import nodemailer from "nodemailer";

const sendEmail = async ({ to, subject, html, text }) => {
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
      to,
      subject,
      html,
      text: text || html,
    });

    console.log("✅ Email sent successfully");
  } catch (error) {
    console.error("❌ Email not sent:", error.message);
    throw new Error("Email could not be sent");
  }
};

export default sendEmail;
