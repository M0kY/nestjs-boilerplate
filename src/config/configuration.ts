import { ConfigurationInterface } from './configuration.interface';

export default (): ConfigurationInterface => ({
  port: parseInt(`${process.env.PORT}`, 10) || 3000,
  serviceName: process.env.SERVICE_NAME || 'nestjs-boilerplate',
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
  security: {
    secret: process.env.PASSWORD_HMAC_SECRET || 'DKk+7aSQumRGXy#=4-VS&4a2k',
    saltRounds: parseInt(`${process.env.BCRYPT_SALT_ROUNDS}`, 10) || 12,
  },
});
