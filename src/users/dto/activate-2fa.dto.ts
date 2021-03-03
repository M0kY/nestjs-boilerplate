import { Field, ObjectType } from '@nestjs/graphql';

@ObjectType('Activate2FA')
export class Activate2faDTO {
  @Field()
  secret: string;

  @Field()
  method: 'TOTP' | 'HOTP';

  @Field()
  uri: string;
}
