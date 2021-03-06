import { CorsOptions } from 'cors';
import { ERROR_CORS_REQUEST_BLOCKED } from '../errors/errorCodes';

const whitelist = [
  `http://localhost:${process.env.SERVER_PORT}`,
  `http://localhost:${process.env.SERVER_PORT}/${process.env.GRAPHQL_ENDPOINT}`,
  `http://localhost:8081/${process.env.GRAPHQL_ENDPOINT}`,
  `http://localhost:3000/${process.env.GRAPHQL_ENDPOINT}`,
  'http://localhost:8081',
  'http://localhost:3000',
];

if (typeof process.env.CORS_WHITELIST_1 !== 'undefined') {
  whitelist.push(decodeURIComponent(process.env.CORS_WHITELIST_1));
}

if (typeof process.env.CORS_WHITELIST_2 !== 'undefined') {
  whitelist.push(decodeURIComponent(process.env.CORS_WHITELIST_2));
}

export const corsOptions: CorsOptions = {
  credentials: true,
  origin: (origin, callback) => {
    if (typeof origin !== 'undefined') {
      if (whitelist.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(
          {
            name: 'CORS',
            message: ERROR_CORS_REQUEST_BLOCKED,
          },
          false,
        );
      }
    } else {
      callback(null, true);
    }
  },
};
