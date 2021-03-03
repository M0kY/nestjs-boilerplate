import { Field, InputType } from '@nestjs/graphql';
import { IsEmail } from 'class-validator';
import { User } from '../models/user.entity';

@InputType({ description: 'User profile data which can be updated' })
export class UpdateProfileInputType implements Partial<User> {
  [key: string]: string;

  @Field({ nullable: true })
  @IsEmail()
  email: string;

  @Field({ nullable: true })
  firstName: string;

  @Field({ nullable: true })
  lastName: string;
}
