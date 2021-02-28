import { ArgsType, Field } from '@nestjs/graphql';
import { Length } from 'class-validator';

@ArgsType()
export class LoginInputType {
  @Field()
  username: string;

  @Field()
  @Length(8, 72)
  password: string;
}
