import { TypeOrmModuleOptions } from '@nestjs/typeorm';

export interface ConfigurationInterface {
  port: number;
  serviceName: string;
  sessionCookieName: string;
  sessionSecret: string;
  database: Promise<TypeOrmModuleOptions> | TypeOrmModuleOptions;
  security: {
    secret: string;
    saltRounds: number | string;
  };
}
