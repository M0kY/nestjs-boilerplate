import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import bcrypt from 'bcrypt';
import { createHmac } from 'crypto';

@Injectable()
export class CryptoService {
  constructor(private readonly configService: ConfigService) {}

  generateHmacSha256Hash = (
    password: string,
    secret: string = this.configService.get('security.secret') as string,
  ) => {
    return createHmac('sha256', secret).update(password).digest('base64');
  };

  hashPassword = (password: string): string => {
    const hmacPasswordHash = this.generateHmacSha256Hash(password);
    return bcrypt.hashSync(
      hmacPasswordHash,
      this.configService.get('security.saltRounds') as number | string,
    );
  };

  comparePasswords = (password: string, hashedPassword: string): boolean => {
    const hmacPasswordHash = this.generateHmacSha256Hash(password);
    return bcrypt.compareSync(hmacPasswordHash, hashedPassword);
  };
}
