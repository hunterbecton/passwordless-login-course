const sgMail = require('@sendgrid/mail');
require('dotenv').config({ path: './config.env' });

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

module.exports = class Email {
  constructor(user, url) {
    this.to = user.email;
    this.url = url;
    this.fromEmail = 'hello@skillthrive.com';
    this.fromName = 'Skillthrive';
  }

  async sendMagicLink() {
    const mailOptions = {
      to: this.to,
      from: {
        email: this.fromEmail,
        name: this.fromName,
      },
      templateId: 'd-0ca886ab0d454cbf8b7c590da3bb0350',
      dynamic_template_data: {
        url: this.url,
      },
    };

    try {
      await sgMail.send(mailOptions);
    } catch (error) {
      console.log(error);
    }
  }
};
