import { MailerService } from '@nestjs-modules/mailer';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApolloError } from 'apollo-server-core';
import { DatabaseError } from 'src/errors/customErrors';
import {
  USER_ACTIVATION_PREFIX,
  USER_RESET_PASSWORD_PREFIX,
} from 'src/redis/constants/redisPrefixes';
import { RedisService } from 'src/redis/redis.service';
import { v4 } from 'uuid';
import {
  ERROR_USER_NOT_FOUND,
  ERROR_WHILE_REDIS_SET,
  ERROR_WHILE_SENDING_EMAIL,
} from '../errors/errorCodes';
import { MailTemplateResult, MailReceiver } from './mail.interface';
import activationMailTemplate from './templates/activationTemplate';
import passwordResetTemplate from './templates/passwordResetTemplate';

@Injectable()
export class MailService {
  constructor(
    private readonly mailerService: MailerService,
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
  ) {}

  private readonly logger = new Logger(MailService.name);

  private async send(
    receiver: MailReceiver,
    { subject, html }: MailTemplateResult,
  ) {
    if (typeof receiver === 'undefined') {
      this.logger.error(`Invalid undefined user provided to mailer`);
      throw new ApolloError(ERROR_USER_NOT_FOUND);
    }

    await this.mailerService
      .sendMail({
        from: `${this.configService.get(
          'mailer.transport',
        )} <${this.configService.get('mailer.transport')}>`,
        to: receiver.email,
        subject,
        html,
      })
      .catch((error: Error) => {
        this.logger.error(error);
        throw new ApolloError(ERROR_WHILE_SENDING_EMAIL);
      });
    this.logger.log(`Successfully sent "${subject}" email.`);
  }

  public async sendActivationMail(receiver: MailReceiver) {
    const activationToken = v4();
    // Set token to be valid for 1 day
    await this.redisService
      .set(USER_ACTIVATION_PREFIX + activationToken, receiver.userId, {
        ttl: 60 * 60 * 24,
      })
      .catch((error: Error) => {
        this.logger.error(error);
        throw new DatabaseError(ERROR_WHILE_REDIS_SET);
      });

    const templateResult = activationMailTemplate(
      this.configService.get('clientUrl'),
      receiver.userId,
      activationToken,
    );

    this.send(receiver, templateResult);
  }

  public async sendPasswordResetMail(receiver: MailReceiver) {
    const resetPasswordToken = v4();
    // Set token to be valid for 1 day
    await this.redisService
      .set(USER_RESET_PASSWORD_PREFIX + resetPasswordToken, receiver.userId, {
        ttl: 60 * 60 * 24,
      })
      .catch((error: Error) => {
        this.logger.error(error);
        throw new DatabaseError(ERROR_WHILE_REDIS_SET);
      });

    const templateResult = passwordResetTemplate(
      this.configService.get('clientUrl'),
      receiver.userId,
      resetPasswordToken,
    );

    this.send(receiver, templateResult);
  }
}
