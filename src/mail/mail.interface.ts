import { User } from '../users/models/user.entity';

export type MailReceiver = Pick<User, 'userId' | 'email'>;

export interface MailTemplateResult {
  subject: string;
  html: string;
}

export interface MailTemplate {
  (...args: any[]): MailTemplateResult;
}

export interface SendMailInput {
  (receiver: MailReceiver, templateType: MailTemplate): Promise<void>;
}
