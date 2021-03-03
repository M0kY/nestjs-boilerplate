import { ArgsType, Field } from '@nestjs/graphql';
import { Length } from 'class-validator';

@ArgsType()
export class BaseLoginType {
  @Field()
  username: string;

  @Field()
  @Length(8, 72)
  password: string;
}

@ArgsType()
export class LoginInputType extends BaseLoginType {
  @Field({ nullable: true })
  @Length(6)
  token?: string;
}
