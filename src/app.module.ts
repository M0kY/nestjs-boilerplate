import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { GraphQLModule } from '@nestjs/graphql';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from './users/users.module';
import { CryptoModule } from './crypto/crypto.module';
import { AuthModule } from './auth/auth.module';
import configuration from './config/configuration';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [configuration],
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('database.host'),
        port: configService.get<number>('database.port'),
        database: configService.get('database.name'),
        username: configService.get('database.username'),
        password: configService.get('database.password'),
        entities: ['dist/**/*.entity{.ts,.js}'],
        synchronize: configService.get('database.synchronize'),
        dropSchema: configService.get('database.dropSchema'),
        retryAttempts: 10,
        retryDelay: 1000,
        autoLoadEntities: true,
      }),
    }),
    GraphQLModule.forRoot({
      cors: true,
      installSubscriptionHandlers: true,
      autoSchemaFile: 'schema.gql',
    }),
    UsersModule,
    UsersModule,
    CryptoModule,
    AuthModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
