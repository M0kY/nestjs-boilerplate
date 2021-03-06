import { ConfigurationInterface } from './configuration.interface';

export default (): ConfigurationInterface => ({
  port: parseInt(`${process.env.SERVER_PORT}`, 10) || 3000,
  graphqlEndpoint: process.env.GRAPHQL_ENDPOINT || '/graphql',
  serviceName: process.env.SERVICE_NAME || 'nestjs-boilerplate',
  clientUrl: process.env.CLIENT_URL || 'http://localhost:3000',
  sessionCookieName: process.env.SESSION_COOKIE_NAME || 'sid',
  sessionSecret: process.env.SESSION_SECRET || 'fsdfdsfdsfdsfsdfsd',
  database: {
    host: process.env.DATABASE_HOST,
    port: parseInt(`${process.env.DATABASE_PORT}`, 10) || 5432,
    username: process.env.DATABASE_USERNAME || 'root',
    password: process.env.DATABASE_PASSWORD || '',
    synchronize: process.env.NODE_ENV !== 'production',
    dropSchema: !!(
      process.env.NODE_ENV === 'development' && process.env.DATABASE_DROP_SCHEMA
    ),
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(`${process.env.REDIS_MASTER_PORT_NUMBER}`, 10) || 6379,
    password: process.env.REDIS_PASSWORD || 'redis',
  },
  security: {
    secret: process.env.PASSWORD_HMAC_SECRET || 'DKk+7aSQumRGXy#=4-VS&4a2k',
    saltRounds: parseInt(`${process.env.BCRYPT_SALT_ROUNDS}`, 10) || 12,
  },
  mailer: {
    transport: {
      host: process.env.MAILER_SMTP_HOST || 'smtp.ethereal.email',
      port: parseInt(`${process.env.MAILER_PORT}`, 10) || 587,
      ignoreTLS: false,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.MAILER_USER || 'opal.toy95@ethereal.email',
        pass: process.env.MAILER_PASSWORD || 'BMGpyQK922vX5VgA8D',
      },
    },
    name: process.env.MAILER_NAME || 'Opal Toy',
  },
});
