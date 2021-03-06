import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { v4 } from 'uuid';
import { AuthenticationError } from 'apollo-server-core';
import { UpdateProfileInputType } from './inputs/profile.input';
import { User } from './models/user.entity';
import { CryptoService } from '../crypto/crypto.service';
import { RegisterInputType } from './inputs/register.input.';
import { DatabaseError } from '../errors/customErrors';
import {
  ERROR_USER_ALREADY_EXISTS,
  ERROR_USER_NOT_FOUND,
  ERROR_WHILE_CREATING_USER,
  ERROR_WHILE_LOOKING_FOR_USER,
  ERROR_WHILE_UPDATING_USER,
} from '../errors/errorCodes';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
    private readonly cryptoService: CryptoService,
  ) {}

  private readonly logger = new Logger(UsersService.name);

  async findById(id: number) {
    const user = await this.usersRepository
      .findOne({ id })
      .catch((error: Error) => {
        this.logger.error(error.message);
        throw new DatabaseError(ERROR_WHILE_LOOKING_FOR_USER);
      });

    if (!user) {
      throw new DatabaseError(ERROR_USER_NOT_FOUND);
    }
    return user;
  }

  async findByUserId(userId: string) {
    const user = await this.usersRepository
      .findOne({ userId })
      .catch((error: Error) => {
        this.logger.error(error.message);
        throw new DatabaseError(ERROR_WHILE_LOOKING_FOR_USER);
      });

    return user;
  }

  async findByUsernameOrEmail(username: string) {
    return await this.usersRepository
      .findOne({
        where: [
          { username: username.toLowerCase() },
          { email: username.toLowerCase() },
        ],
      })
      .catch((error: Error) => {
        this.logger.error(error.message);
        throw new DatabaseError(ERROR_WHILE_LOOKING_FOR_USER);
      });
  }

  async findByEmail(email: string) {
    return await this.usersRepository
      .findOne({ email })
      .catch((error: Error) => {
        this.logger.error(error.message);
        throw new DatabaseError(ERROR_WHILE_LOOKING_FOR_USER);
      });
  }

  async getAll() {
    return await this.usersRepository.find().catch((error: Error) => {
      this.logger.error(error.message);
      throw new DatabaseError(ERROR_WHILE_LOOKING_FOR_USER);
    });
  }

  async createUser(data: RegisterInputType) {
    const user = new User();

    user.userId = v4();
    user.username = data.username.toLowerCase();
    user.displayName = data.username;
    user.email = data.email.toLowerCase();
    user.password = this.cryptoService.hashPassword(data.password);

    return this.usersRepository.save(user).catch((error: any) => {
      this.logger.error(error.message);
      if (error.code === '23505') {
        throw new AuthenticationError(ERROR_USER_ALREADY_EXISTS);
      }
      throw new DatabaseError(ERROR_WHILE_CREATING_USER);
    });
  }

  async updatePassword(user: User, newPassword: string) {
    user.password = this.cryptoService.hashPassword(newPassword);
    await this.usersRepository.save(user).catch((error: Error) => {
      this.logger.error(error.message);
      throw new DatabaseError(ERROR_WHILE_UPDATING_USER);
    });
  }

  async updateUserProfile(
    id: number,
    updateProfileData: UpdateProfileInputType,
  ) {
    const user: any = await this.findById(id).catch((error: Error) => {
      this.logger.error(error.message);
      throw new DatabaseError(ERROR_WHILE_LOOKING_FOR_USER);
    });

    Object.keys(updateProfileData).forEach(key => {
      if (updateProfileData[key] !== undefined) {
        user[key] = updateProfileData[key];
      }
    });

    return this.usersRepository.save(user).catch((error: Error) => {
      this.logger.error(error.message);
      throw new DatabaseError(ERROR_WHILE_UPDATING_USER);
    });
  }

  async updateUser(id: number, data: Partial<User>) {
    return this.usersRepository.update(id, data).catch((error: Error) => {
      this.logger.error(error.message);
      throw new DatabaseError(ERROR_WHILE_UPDATING_USER);
    });
  }

  async failedLoginAttempt(user: User) {
    user.loginAttempts++;
    if (user.loginAttempts >= 10) {
      user.locked = true;
    }

    await this.usersRepository.save(user).catch((error: Error) => {
      this.logger.error(error.message);
      throw new DatabaseError(ERROR_WHILE_UPDATING_USER);
    });
  }

  async resetLoginAttempts(id: number) {
    return this.usersRepository
      .update(id, { loginAttempts: 0 })
      .catch((error: Error) => {
        this.logger.error(error.message);
        throw new DatabaseError(ERROR_WHILE_UPDATING_USER);
      });
  }
}
