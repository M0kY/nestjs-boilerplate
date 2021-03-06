import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import * as compression from 'compression';
import * as helmet from 'helmet';
import { AppModule } from './app.module';
import { corsOptions } from './utils/corsOptions';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const configService = app.get(ConfigService);
  const logger = new Logger(AppModule.name);

  const port = configService.get('port');

  app.enableCors(corsOptions);
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: [`*`],
          styleSrc: [
            `'self'`,
            `'unsafe-inline'`,
            'cdn.jsdelivr.net',
            'fonts.googleapis.com',
          ],
          fontSrc: [`'self'`, 'fonts.gstatic.com'],
          imgSrc: [`'self'`, 'data:', 'cdn.jsdelivr.net'],
          scriptSrc: [`'self'`, `https: 'unsafe-inline'`, `cdn.jsdelivr.net`],
        },
      },
    }),
  );
  app.use(compression());

  await app.listen(port);
  logger.log(`Server is running on: ${await app.getUrl()}`);
}
bootstrap();
