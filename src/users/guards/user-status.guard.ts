import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { ForbiddenError } from 'apollo-server-core';
import { ERROR_USER_NOT_ACTIVE } from 'src/errors/errorCodes';

@Injectable()
export class UserStatusGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const ctx = GqlExecutionContext.create(context);

    const { user } = ctx.getContext().req;
    const info = ctx.getInfo();

    if (user) {
      // Ignore check for "me" resolver to be able to fetch user data
      if (!user.activated && info.fieldName !== 'me') {
        throw new ForbiddenError(ERROR_USER_NOT_ACTIVE);
      }

      if (user.locked) {
        throw new ForbiddenError(ERROR_USER_NOT_ACTIVE);
      }

      if (user.disabled) {
        throw new ForbiddenError(ERROR_USER_NOT_ACTIVE);
      }
    }

    return true;
  }
}
