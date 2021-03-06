import { Args, Query, Mutation, Resolver } from '@nestjs/graphql';
import { Injectable, Logger, UseGuards } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApolloError,
  AuthenticationError,
  ForbiddenError,
} from 'apollo-server-core';
import { authenticator } from 'otplib';

// import { PermissionsMiddleware } from '../../middleware/permissionsMIddleware';
import { UsersService } from './users.service';
import { User } from '../users/models/user.entity';
// import { Role } from '../enums/Role.enum';
import { UpdateProfileInputType } from './inputs/profile.input';
import { User2FA } from './interfaces/user-2fa.interface';
import { CryptoService } from '../crypto/crypto.service';
import { AuthService } from '../auth/auth.service';
import { RegisterInputType } from './inputs/register.input.';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { GqlAuthGuard } from '../auth/guards/graphql-jwt-auth.guard';
import { LoginDTO } from './dto/login.dto';
import { LoginInputType } from './inputs/login.input';
import { Activate2faDTO } from './dto/activate-2fa.dto';
import { ChangePasswordDTO } from './dto/change-password.dto';
import { ResetPasswordInput } from './inputs/reset-password.input';
import { AccountActivationDTO } from './dto/account-activation.dto';
import {
  ERROR_2FA_ALREADY_VERIFIED,
  ERROR_2FA_NOT_ACTIVE,
  ERROR_2FA_TOKEN_REQUIRED,
  ERROR_INVALID_2FA_TOKEN,
  ERROR_INVALID_LOGIN,
  ERROR_NO_2FA_SECRET,
  ERROR_USER_ALREADY_ACTIVE,
  ERROR_USER_NOT_FOUND,
} from '../errors/errorCodes';
import { Roles } from 'src/Roles/roles.decorator';
import { Role } from 'src/Roles/Role.enum';
import { RolesGuard } from 'src/Roles/roles.guard';
import { UserStatusGuard } from './guards/user-status.guard';

@Injectable()
@Resolver(User)
export class UsersResolver {
  constructor(
    private readonly userService: UsersService,
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly cryptoService: CryptoService,
  ) {}

  private readonly logger = new Logger(UsersResolver.name);

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

  @Mutation(() => LoginDTO, { nullable: true })
  async login(@Args() { username, password, token }: LoginInputType) {
    const user = await this.userService.findByUsernameOrEmail(username);

    if (!user) {
      throw new AuthenticationError(ERROR_INVALID_LOGIN);
    }

    const valid = this.cryptoService.comparePasswords(password, user.password);

    if (!valid) {
      await this.userService.failedLoginAttempt(user);
      throw new AuthenticationError(ERROR_INVALID_LOGIN);
    }

    if (user.enabled2fa) {
      if (!token) {
        await this.userService.failedLoginAttempt(user);
        throw new AuthenticationError(ERROR_2FA_TOKEN_REQUIRED);
      }

      if (!user.secret2fa) {
        this.logger.error(ERROR_NO_2FA_SECRET, 'LOGIN');
        throw new ApolloError(ERROR_NO_2FA_SECRET);
      }

      const isTokenValid = authenticator.verify({
        token,
        secret: user.secret2fa,
      });

      if (!isTokenValid) {
        await this.userService.failedLoginAttempt(user);
        throw new AuthenticationError(ERROR_INVALID_2FA_TOKEN);
      }
    }

    await this.userService
      .resetLoginAttempts(user.id)
      .then(() => (user.loginAttempts = 0));

    const jwtTokens = await this.authService.login(user);

    return { ...user, access_token: jwtTokens.access_token };
  }

  // @UseMiddleware(PermissionsMiddleware)
  @UseGuards(UserStatusGuard)
  @UseGuards(GqlAuthGuard)
  @Query(() => User, { nullable: true })
  async me(@CurrentUser() user: User): Promise<User | null> {
    return await this.userService.findById(user.id);
  }

  // @UseMiddleware(PermissionsMiddleware)
  @UseGuards(UserStatusGuard)
  @Roles(Role.USER)
  @UseGuards(RolesGuard)
  @UseGuards(GqlAuthGuard)
  @Query(() => [User])
  async getAllUsers(): Promise<User[]> {
    return (await this.userService.getAll()) || [];
  }

  // @UseMiddleware(PermissionsMiddleware)
  @UseGuards(GqlAuthGuard)
  @Mutation(() => ChangePasswordDTO, { nullable: true })
  async changePassword(
    @Args('currentPassword') currentPassword: string,
    @Args('newPassword') newPassword: string,
    @CurrentUser() user: User,
    @Args('token', { nullable: true }) token?: string,
  ): Promise<ChangePasswordDTO> {
    if (!this.cryptoService.comparePasswords(currentPassword, user.password)) {
      // throw new CustomError({
      //   ...ERROR_INVALID_PASSWORD_INPUT),
      //   properties: { invalidArgument: 'currentPassword' },
      // });
    }

    if (user.enabled2fa) {
      if (!token) {
        throw new AuthenticationError(ERROR_INVALID_2FA_TOKEN);
      }

      if (!user.secret2fa) {
        this.logger.error(ERROR_NO_2FA_SECRET, 'CHANGE PASSWORD');
        throw new ApolloError(ERROR_NO_2FA_SECRET);
      }

      const isTokenValid = authenticator.verify({
        token,
        secret: user.secret2fa,
      });

      if (!isTokenValid) {
        throw new AuthenticationError(ERROR_INVALID_2FA_TOKEN);
      }
    }

    await this.userService.updatePassword(user, newPassword);

    return { userId: user.userId, passwordChanged: true };
  }

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

  // @UseMiddleware(PermissionsMiddleware)
  @UseGuards(GqlAuthGuard)
  @Mutation(() => Activate2faDTO)
  async activate2fa(@CurrentUser() user: User): Promise<Activate2faDTO> {
    if (user.enabled2fa) {
      throw new ForbiddenError(ERROR_2FA_ALREADY_VERIFIED);
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

  // @UseMiddleware(PermissionsMiddleware)
  @UseGuards(GqlAuthGuard)
  @Mutation(() => Boolean)
  async verifyOrDeactivate2fa(
    @Args('token') token: string,
    @Args('enable') enable: boolean,
    @CurrentUser() user: User,
  ): Promise<boolean> {
    if (!user.secret2fa) {
      throw new ApolloError(ERROR_NO_2FA_SECRET);
    }

    const isValid = authenticator.verify({ token, secret: user.secret2fa });

    if (!isValid) {
      throw new AuthenticationError(ERROR_INVALID_2FA_TOKEN);
    }

    let updated2fa: User2FA = {};

    if (enable) {
      if (user.enabled2fa) {
        throw new ForbiddenError(ERROR_2FA_ALREADY_VERIFIED);
      }

      updated2fa = { enabled2fa: true };
    } else {
      if (!user.enabled2fa) {
        throw new ForbiddenError(ERROR_2FA_NOT_ACTIVE);
      }
      updated2fa = { enabled2fa: false, secret2fa: null };
    }

    await this.userService.updateUser(user.id, updated2fa);

    return true;
  }

  @Mutation(() => AccountActivationDTO)
  async activate(
    @Args('userId') userId: string,
    @Args('token') token: string,
  ): Promise<AccountActivationDTO> {
    // const id = await redis
    //   .get(USER_ACTIVATION_PREFIX + token)
    //   .catch((error: Error) => {
    //     // logger.error(error);
    //     // throw new CustomError(ERROR_WHILE_REDIS_LOOKUP));
    //   });

    // if (!id || id !== userId) {
    //   // throw new CustomError(ERROR_INVALID_TOKEN));
    // }

    const user = await this.userService.findByUserId(userId);

    if (!user) {
      throw new AuthenticationError(ERROR_USER_NOT_FOUND);
    }

    if (user.activated) {
      throw new ForbiddenError(ERROR_USER_ALREADY_ACTIVE);
    }

    await this.userService.updateUser(user.id, { activated: true });

    // await redis.del(USER_ACTIVATION_PREFIX + token).catch((error: Error) => {
    //   // logger.error(error);
    //   // throw new CustomError(ERROR_WHILE_REDIS_DELETE));
    // });

    return { userId, activated: true };
  }

  @Mutation(() => Boolean)
  async resendActivationLink(@Args('email') email: string): Promise<boolean> {
    const user = await this.userService.findByEmail(email);
    if (user && !user.activated) {
      // Mail.sendActivationMail(user);
    }

    return true;
  }

  @Mutation(() => Boolean)
  async resetPasswordRequest(@Args('email') email: string): Promise<boolean> {
    const user = await this.userService.findByEmail(email);
    if (user) {
      // Mail.sendPasswordResetMail(user);
    }

    return true;
  }

  @Mutation(() => ChangePasswordDTO)
  async resetPassword(
    @Args() { userId, resetToken, newPassword }: ResetPasswordInput,
  ): Promise<ChangePasswordDTO> {
    // const id = await redis
    //   .get(USER_RESET_PASSWORD_PREFIX + resetToken)
    //   .catch((error: Error) => {
    //     // logger.error(error);
    //     // throw new CustomError(ERROR_WHILE_REDIS_DELETE));
    //   });

    // if (!id || id !== userId) {
    //   // throw new CustomError(ERROR_INVALID_TOKEN));
    // }

    const user = await this.userService.findByUserId(userId);

    if (!user) {
      throw new AuthenticationError(ERROR_USER_NOT_FOUND);
    }

    await this.userService.updateUser(user.id, {
      password: this.cryptoService.hashPassword(newPassword),
    });
    // await redis
    //   .del(USER_RESET_PASSWORD_PREFIX + resetToken)
    //   .catch((error: Error) => {
    //     // logger.error(error);
    //     // throw new CustomError(ERROR_WHILE_REDIS_DELETE));
    //   });

    return { userId, passwordChanged: true };
  }
}
