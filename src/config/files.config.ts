import { registerAs } from '@nestjs/config';

export const filesConfig = registerAs('files', () => ({
  basePath : process.env.BASE_FILES_PATH || './uploads',
  baseUrl  : process.env.BASE_URL || 'localhost:3000',
}));
