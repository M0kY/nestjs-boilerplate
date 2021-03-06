import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/users/models/user.entity';
import { UsersService } from '../users/users.service';

interface JwtLoginReturnType {
  access_token: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(userId: string): Promise<User | null> {
    const user = await this.usersService.findByUserId(userId);
    return user || null;
  }

  async login(user: any): Promise<JwtLoginReturnType> {
    const payload = { sub: user.userId, username: user.username };

    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
