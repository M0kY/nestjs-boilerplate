import { Field, ID, ObjectType } from '@nestjs/graphql';
import { Role } from 'src/enums/Role.enum';
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Unique,
  UpdateDateColumn,
  CreateDateColumn,
} from 'typeorm';

@ObjectType()
@Entity()
@Unique(['username', 'email'])
export class User {
  @Field(() => ID)
  @PrimaryGeneratedColumn({ type: 'integer' })
  id: number;

  @Field()
  @Column()
  username: string;

  @Field()
  @Column()
  displayName: string;

  @Column()
  password: string;

  @Field()
  @Column({ unique: true })
  email: string;

  @Field({ nullable: true })
  @Column({ nullable: true })
  firstName: string;

  @Field({ nullable: true })
  @Column({ nullable: true })
  lastName: string;

  @Field(() => Role)
  @Column({ type: 'enum', enum: Role, default: Role.USER })
  role: Role;

  @Field()
  @Column({ default: false })
  activated: boolean;

  @Field()
  @Column({ default: false })
  enabled2fa: boolean;

  @Column({ type: String, nullable: true })
  secret2fa?: string | null;

  @Field()
  @Column({ type: 'integer', default: 0 })
  loginAttempts: number;

  @Field()
  @Column({ default: false })
  locked: boolean;

  @Field()
  @Column({ default: false })
  disabled: boolean;

  @Field(() => Date)
  @CreateDateColumn()
  createdAt: string;

  @Field(() => Date)
  @UpdateDateColumn()
  updatedAt: string;
}
