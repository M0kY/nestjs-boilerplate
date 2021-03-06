export enum ErrorCode {
  DATABASE_ERROR = 'DATABASE_ERROR',
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  FORBIDDEN_ERROR = 'FORBIDDEN_ERROR',
  USER_INPUT_ERROR = 'USER_INPUT_ERROR',
  CORS_ERROR = 'CORS_ERROR',
}

export interface CustomErrorDTO {
  code: ErrorCode;
  key: string;
  message: string;
  properties?: Record<string, any>;
}

export interface ErrorsObject {
  [key: string]: {
    code: ErrorCode;
    message: string;
  };
}
