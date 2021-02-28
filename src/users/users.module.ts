import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersResolver } from './users.resolver';
import { CryptoModule } from '../crypto/crypto.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './models/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User]), CryptoModule],
  providers: [UsersService, UsersResolver],
  exports: [TypeOrmModule],
})
export class UsersModule {}
