import { Field, ID, ObjectType } from '@nestjs/graphql';

@ObjectType('ChangePassword')
export class ChangePasswordDTO {
  @Field(() => ID)
  userId: string;
  @Field(() => Boolean)
  passwordChanged: boolean;
}
