import { ArgsType, Field } from '@nestjs/graphql';
import { IsEmail } from 'class-validator';
import { LoginInputType } from './login-input.dto';

@ArgsType()
export class RegisterInputType extends LoginInputType {
  @Field()
  @IsEmail()
  email: string;
}
