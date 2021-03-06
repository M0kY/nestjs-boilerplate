import { MailerOptions } from '@nestjs-modules/mailer';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { RedisOptions } from 'ioredis';

interface MailerConfig extends Pick<MailerOptions, 'transport'> {
  name: string;
}

export interface ConfigurationInterface {
  port: number;
  graphqlEndpoint: string;
  serviceName: string;
  clientUrl: string;
  sessionCookieName: string;
  sessionSecret: string;
  database: Promise<TypeOrmModuleOptions> | TypeOrmModuleOptions;
  redis: RedisOptions;
  security: {
    secret: string;
    saltRounds: number | string;
  };
  mailer: MailerConfig;
}
