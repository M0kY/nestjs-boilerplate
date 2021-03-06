import { MailTemplate } from '../mail.interface';

const activationMailTemplate: MailTemplate = (
  clientUrl: string,
  userId: string,
  activationToken: string,
) => {
  const html = `<p>Activation code: ${clientUrl}/activate/${userId}/${activationToken}</p>`;

  return {
    subject: 'Activate account',
    html,
  };
};

export default activationMailTemplate;
