import { Field, ObjectType } from '@nestjs/graphql';
import { User } from '../models/user.entity';

@ObjectType('LoginReturnType')
export class LoginDTO extends User {
  @Field()
  access_token: string;
}
