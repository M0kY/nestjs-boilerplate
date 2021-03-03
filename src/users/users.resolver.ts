import {
  Args,
  Field,
  ID,
  Query,
  Mutation,
  ObjectType,
  Resolver,
} from '@nestjs/graphql';
import { Injectable, UseGuards } from '@nestjs/common';

import { authenticator } from 'otplib';

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
import { AuthService } from 'src/auth/auth.service';
import { RegisterInputType } from './dto/register-input.dto';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { GqlAuthGuard } from 'src/auth/guards/jwt-auth.guard';

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

@ObjectType()
class LoginReturnType extends User {
  @Field()
  access_token: string;
}

@Injectable()
@Resolver(User)
export class UsersResolver {
  constructor(
    private readonly userService: UsersService,
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly cryptoService: CryptoService,
  ) {}

  @Mutation(() => User, { nullable: true })
  async register(
    @Args() { username, email, password }: RegisterInputType,
  ): Promise<User> {
    const user = await this.userService.createUser({
      username,
      email,
      password,
    });

    // Mail.sendPasswordResetMail(user);

    return user;
  }

  @Mutation(() => LoginReturnType, { nullable: true })
  async login(
    @Args('username') username: string,
    @Args('password') password: string,
    @Args('token', { nullable: true }) token?: string,
  ) {
    const user = await this.userService.findByUsernameOrEmail(username);

    if (!user) {
      // throw new CustomError(getErrorByKey(ERROR_INVALID_LOGIN));
      throw new Error();
    }

    const valid = this.cryptoService.comparePasswords(password, user.password);

    if (!valid) {
      await this.userService.failedLoginAttempt(user);
      // throw new CustomError(getErrorByKey(ERROR_INVALID_LOGIN));
      throw new Error();
    }

    if (user.enabled2fa) {
      if (!token) {
        await this.userService.failedLoginAttempt(user);
        // throw new CustomError(getErrorByKey(ERROR_2FA_TOKEN_REQUIRED));
        throw new Error();
      }

      if (!user.secret2fa) {
        // logger.error(getErrorByKey(ERROR_NO_2FA_SECRET).message, 'LOGIN');
        // throw new CustomError(getErrorByKey(ERROR_NO_2FA_SECRET));
        throw new Error();
      }

      const isTokenValid = authenticator.verify({
        token,
        secret: user.secret2fa,
      });

      if (!isTokenValid) {
        await this.userService.failedLoginAttempt(user);
        // throw new CustomError(getErrorByKey(ERROR_INVALID_2FA_TOKEN));
        throw new Error();
      }
    }

    await this.userService
      .resetLoginAttempts(user.id)
      .then(() => (user.loginAttempts = 0));

    const jwtTokens = await this.authService.login(user);

    return { ...user, access_token: jwtTokens.access_token };
  }

  // @Authorized()
  // @UseMiddleware(PermissionsMiddleware)
  @UseGuards(GqlAuthGuard)
  @Query(() => User, { nullable: true })
  async me(@CurrentUser() user: User): Promise<User | null> {
    return await this.userService.findById(user.id);
  }

  // @Authorized(Role.ADMIN)
  // @UseMiddleware(PermissionsMiddleware)
  @UseGuards(GqlAuthGuard)
  @Query(() => [User])
  async getAllUsers(): Promise<User[]> {
    return (await this.userService.getAll()) || [];
  }

  // @Authorized()
  // @UseMiddleware(PermissionsMiddleware)
  @UseGuards(GqlAuthGuard)
  @Mutation(() => ChangePasswordData, { nullable: true })
  async changePassword(
    @Args('currentPassword') currentPassword: string,
    @Args('newPassword') newPassword: string,
    @CurrentUser() user: User,
    @Args('token', { nullable: true }) token?: string,
  ): Promise<ChangePasswordData> {
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
  @UseGuards(GqlAuthGuard)
  @Mutation(() => User, { nullable: true })
  async updateProfile(
    @Args('data') updateProfileData: UpdateProfileInputType,
    @CurrentUser() user: User,
  ): Promise<User> {
    const updatedUser = await this.userService.updateUserProfile(
      user.id,
      updateProfileData,
    );
    return updatedUser;
  }

  // @Authorized()
  // @UseMiddleware(PermissionsMiddleware)
  @UseGuards(GqlAuthGuard)
  @Mutation(() => Activate2faData)
  async activate2fa(@CurrentUser() user: User): Promise<Activate2faData> {
    if (user.enabled2fa) {
      // throw new CustomError(getErrorByKey(ERROR_2FA_ALREADY_VERIFIED));
      throw new Error();
    }

    const secret = authenticator.generateSecret();

    await this.userService.updateUser(user.id, {
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
  @UseGuards(GqlAuthGuard)
  @Mutation(() => Boolean)
  async verifyOrDeactivate2fa(
    @Args('token') token: string,
    @Args('enable') enable: boolean,
    @CurrentUser() user: User,
  ): Promise<boolean> {
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

    await this.userService.updateUser(user.id, update2faDTO);

    return true;
  }
}
