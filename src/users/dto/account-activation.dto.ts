import { Field, ID, ObjectType } from '@nestjs/graphql';

@ObjectType('AccountActivation')
export class AccountActivationDTO {
  @Field(() => ID)
  userId: string;
  @Field(() => Boolean)
  activated: boolean;
}
