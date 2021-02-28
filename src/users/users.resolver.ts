import {
  Args,
  Field,
  ID,
  Query,
  Mutation,
  ObjectType,
  Resolver,
  Context,
} from '@nestjs/graphql';
import { Injectable } from '@nestjs/common';

import { authenticator } from 'otplib';

import { ResolverContext } from '../types/ResolverContext';

// import {
//   CustomError,
//   getErrorByKey,
//   ERROR_INVALID_PASSWORD_INPUT,
//   ERROR_INVALID_2FA_TOKEN,
//   ERROR_NO_2FA_SECRET,
//   ERROR_2FA_ALREADY_VERIFIED,
//   ERROR_2FA_NOT_ACTIVE,
// } from '../../constants/errorCodes';

// import { PermissionsMiddleware } from '../../middleware/permissionsMIddleware';
import { UsersService } from './users.service';
import { User } from '../users/models/user.entity';
// import { Role } from 'src/enums/Role.enum';
import { UpdateProfileInputType } from './dto/profile-input.dto';
import { User2faDTO } from './dto/user-2fa.dto';
import { CryptoService } from '../crypto/crypto.service';
import { ConfigService } from '@nestjs/config';

@ObjectType()
class ChangePasswordData {
  @Field(() => ID)
  id: string;
  @Field(() => Boolean)
  passwordChanged: boolean;
}

@ObjectType()
class Activate2faData {
  @Field()
  secret: string;
  @Field()
  method: 'TOTP' | 'HOTP';
  @Field()
  uri: string;
}

@Injectable()
@Resolver(User)
export class UsersResolver {
  constructor(
    private readonly userService: UsersService,
    private readonly configService: ConfigService,
    private readonly cryptoService: CryptoService,
  ) {}

  // @Authorized()
  // @UseMiddleware(PermissionsMiddleware)
  @Query(() => User, { nullable: true })
  async me(@Context() ctx: ResolverContext): Promise<User | void> {
    return await this.userService.findById('1');
  }

  // @Authorized(Role.ADMIN)
  // @UseMiddleware(PermissionsMiddleware)
  @Query(() => [User])
  async getAllUsers(): Promise<User[]> {
    return (await this.userService.getAll()) || [];
  }

  // @Authorized()
  // @UseMiddleware(PermissionsMiddleware)
  @Mutation(() => ChangePasswordData, { nullable: true })
  async changePassword(
    @Args('currentPassword') currentPassword: string,
    @Args('newPassword') newPassword: string,
    @Context() ctx: ResolverContext,
    @Args('token', { nullable: true }) token?: string,
  ): Promise<ChangePasswordData> {
    const user = await this.userService.findById('1');

    if (!this.cryptoService.comparePasswords(currentPassword, user.password)) {
      // throw new CustomError({
      //   ...getErrorByKey(ERROR_INVALID_PASSWORD_INPUT),
      //   properties: { invalidArgument: 'currentPassword' },
      // });
    }

    if (user.enabled2fa) {
      if (!token) {
        // throw new CustomError(getErrorByKey(ERROR_INVALID_2FA_TOKEN));
        throw new Error();
      }

      if (!user.secret2fa) {
        // logger.error(
        //   getErrorByKey(ERROR_NO_2FA_SECRET).message,
        //   'CHANGE PASSWORD',
        // );
        // throw new CustomError(getErrorByKey(ERROR_NO_2FA_SECRET));
        throw new Error();
      }

      const isTokenValid = authenticator.verify({
        token,
        secret: user.secret2fa,
      });

      if (!isTokenValid) {
        // throw new CustomError(getErrorByKey(ERROR_INVALID_2FA_TOKEN));
        throw new Error();
      }
    }

    await this.userService.updatePassword(user, newPassword);

    return { id: user.id.toString(), passwordChanged: true };
  }

  // @Authorized()
  // @UseMiddleware(PermissionsMiddleware)
  @Mutation(() => User, { nullable: true })
  async updateProfile(
    @Args('data') updateProfileData: UpdateProfileInputType,
    @Context() ctx: ResolverContext,
  ): Promise<User> {
    const user = await this.userService.updateUserProfile(
      '1',
      updateProfileData,
    );
    return user;
  }

  // @Authorized()
  // @UseMiddleware(PermissionsMiddleware)
  @Mutation(() => Activate2faData)
  async activate2fa(@Context() ctx: ResolverContext): Promise<Activate2faData> {
    const user = await this.userService.findById('1');

    if (user.enabled2fa) {
      // throw new CustomError(getErrorByKey(ERROR_2FA_ALREADY_VERIFIED));
      throw new Error();
    }

    const secret = authenticator.generateSecret();

    await this.userService.updateUser('1', {
      secret2fa: secret,
    });

    const uri = authenticator.keyuri(
      user.email,
      this.configService.get('serviceName') as string,
      secret,
    );

    return {
      secret,
      method: 'TOTP',
      uri,
    };
  }

  // @Authorized()
  // @UseMiddleware(PermissionsMiddleware)
  @Mutation(() => Boolean)
  async verifyOrDeactivate2fa(
    @Args('token') token: string,
    @Args('enable') enable: boolean,
    @Context() ctx: ResolverContext,
  ): Promise<boolean> {
    const user = await this.userService.findById('1');

    if (!user.secret2fa) {
      // throw new CustomError(getErrorByKey(ERROR_NO_2FA_SECRET));
      throw new Error();
    }

    const isValid = authenticator.verify({ token, secret: user.secret2fa });

    if (!isValid) {
      // throw new CustomError(getErrorByKey(ERROR_INVALID_2FA_TOKEN));
      throw new Error();
    }

    let update2faDTO: User2faDTO = {};

    if (enable) {
      if (user.enabled2fa) {
        // throw new CustomError(getErrorByKey(ERROR_2FA_ALREADY_VERIFIED));
        throw new Error();
      }

      update2faDTO = { enabled2fa: true };
    } else {
      if (!user.enabled2fa) {
        // throw new CustomError(getErrorByKey(ERROR_2FA_NOT_ACTIVE));
        throw new Error();
      }
      update2faDTO = { enabled2fa: false, secret2fa: null };
    }

    await this.userService.updateUser('1', update2faDTO);

    return true;
  }
}
