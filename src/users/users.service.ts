import { Injectable } from '@nestjs/common';

import { InjectRepository } from '@nestjs/typeorm';
import { UpdateProfileInputType } from './dto/profile-input.dto';
import { User } from './models/user.entity';
import { Repository } from 'typeorm';
import { CryptoService } from '../crypto/crypto.service';
import { RegisterInputType } from './dto/register-input.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private cryptoService: CryptoService,
  ) {}

  async findById(id: string) {
    const user = await this.usersRepository
      .findOne({ id: parseInt(id, 10) })
      .catch((error: Error) => {
        //logger.error(error);
        //throw new CustomError(getErrorByKey(ERROR_WHILE_LOOKING_FOR_USER));
        throw new Error();
      });

    if (!user) {
      //throw new CustomError(getErrorByKey(ERROR_USER_NOT_FOUND));
      throw new Error();
    }
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
        //logger.error(error);
        //throw new CustomError(getErrorByKey(ERROR_WHILE_LOOKING_FOR_USER));
        throw new Error();
      });
  }

  async findByEmail(email: string) {
    return await this.usersRepository
      .findOne({ email })
      .catch((error: Error) => {
        //logger.error(error);
        //throw new CustomError(getErrorByKey(ERROR_WHILE_LOOKING_FOR_USER));
        throw new Error();
      });
  }

  async getAll() {
    return await this.usersRepository.find().catch((error: Error) => {
      //logger.error(error);
      //throw new CustomError(getErrorByKey(ERROR_WHILE_LOOKING_FOR_USER));
      throw new Error();
    });
  }

  async createUser(data: RegisterInputType) {
    const user = new User();

    user.username = data.username.toLowerCase();
    user.displayName = data.username;
    user.email = data.email.toLowerCase();
    user.password = this.cryptoService.hashPassword(data.password);

    return this.usersRepository.save(user).catch((error: Error) => {
      //logger.error(error);
      //throw new CustomError(getErrorByKey(ERROR_WHILE_CREATING_USER));
      throw new Error();
    });
  }

  async updatePassword(user: User, newPassword: string) {
    user.password = this.cryptoService.hashPassword(newPassword);
    await this.usersRepository.save(user).catch((error: Error) => {
      //logger.error(error);
      //throw new CustomError(getErrorByKey(ERROR_WHILE_UPDATING_USER));
      throw new Error();
    });
  }

  async updateUserProfile(
    id: string,
    updateProfileData: UpdateProfileInputType,
  ) {
    const user: any = await this.findById(id).catch((error: Error) => {
      //logger.error(error);
      //throw new CustomError(getErrorByKey(ERROR_WHILE_LOOKING_FOR_USER));
      throw new Error();
    });

    Object.keys(updateProfileData).forEach(key => {
      if (updateProfileData[key] !== undefined) {
        user[key] = updateProfileData[key];
      }
    });

    return this.usersRepository.save(user).catch((error: Error) => {
      //logger.error(error);
      //throw new CustomError(getErrorByKey(ERROR_WHILE_UPDATING_USER));
      throw new Error();
    });
  }

  async updateUser(id: string, data: Partial<User>) {
    return this.usersRepository.update(id, data).catch((error: Error) => {
      //logger.error(error);
      //throw new CustomError(getErrorByKey(ERROR_WHILE_UPDATING_USER));
      throw new Error();
    });
  }

  async failedLoginAttempt(user: User) {
    user.loginAttempts++;
    if (user.loginAttempts >= 10) {
      user.locked = true;
    }

    await this.usersRepository.save(user).catch((error: Error) => {
      //logger.error(error);
      //throw new CustomError(getErrorByKey(ERROR_WHILE_UPDATING_USER));
      throw new Error();
    });
  }

  async resetLoginAttempts(id: number) {
    return this.usersRepository
      .update(id, { loginAttempts: 0 })
      .catch((error: Error) => {
        //logger.error(error);
        //throw new CustomError(getErrorByKey(ERROR_WHILE_UPDATING_USER));
        throw new Error();
      });
  }
}
