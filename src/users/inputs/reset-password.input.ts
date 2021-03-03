import { ArgsType, Field, ID } from '@nestjs/graphql';
import { Length } from 'class-validator';

@ArgsType()
export class ResetPasswordInput {
  @Field(() => ID)
  userId: string;

  @Field()
  resetToken: string;

  @Field()
  @Length(8, 72)
  newPassword: string;
}
