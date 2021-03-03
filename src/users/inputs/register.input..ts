import { ArgsType, Field } from '@nestjs/graphql';
import { IsEmail } from 'class-validator';
import { BaseLoginType } from './login.input';

@ArgsType()
export class RegisterInputType extends BaseLoginType {
  @Field()
  @IsEmail()
  email: string;
}
