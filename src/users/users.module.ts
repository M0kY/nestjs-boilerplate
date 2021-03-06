import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersResolver } from './users.resolver';
import { CryptoModule } from '../crypto/crypto.module';
import { AuthModule } from '../auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './models/user.entity';
import { RedisModule } from 'src/redis/redis.module';
import { MailModule } from '../mail/mail.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    CryptoModule,
    AuthModule,
    RedisModule,
    MailModule,
  ],
  providers: [UsersService, UsersResolver],
  exports: [TypeOrmModule, UsersService],
})
export class UsersModule {}
