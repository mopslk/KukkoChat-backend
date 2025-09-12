import { registerAs } from '@nestjs/config';

export const keysConfig = registerAs('keys', () => ({
  jwtSecret        : process.env.JWT_SECRET_KEY,
  jwtRefreshSecret : process.env.JWT_REFRESH_SECRET_KEY,
  encryptPrivate   : process.env.ENCRYPT_PRIVATE_KEY,
}));
