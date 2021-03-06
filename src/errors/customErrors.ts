import { ApolloError } from 'apollo-server-core';
import { CustomErrorDTO } from './interfaces/error.interface';

export class CustomError extends ApolloError {
  constructor({ message, code, key, properties }: CustomErrorDTO) {
    super(message, code, { key, ...properties });

    Object.defineProperty(this, 'name', { value: 'CustomError' });
  }
}

export class DatabaseError extends ApolloError {
  constructor(message: string) {
    super(message, 'DATABASE_ERROR');

    Object.defineProperty(this, 'name', { value: 'DatabaseError' });
  }
}
