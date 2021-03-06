import { MailTemplate } from '../mail.interface';

const passwordResetTemplate: MailTemplate = (
  clientUrl: string,
  userId: string,
  resetPasswordToken: string,
) => {
  const html = `<p>Activation code: ${clientUrl}/reset-password/${userId}/${resetPasswordToken}</p>`;

  return {
    subject: 'Reset password',
    html,
  };
};

export default passwordResetTemplate;
