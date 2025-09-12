import { registerAs } from '@nestjs/config';

export const postgresConfig = registerAs('postgres', () => ({
  host     : process.env.DB_HOST || 'localhost',
  port     : process.env.DB_PORT || 5432,
  userName : process.env.DB_USERNAME,
  password : process.env.DB_PASSWORD,
  baseName : process.env.DB_DATABASE,
  url      : process.env.DATABASE_URL,
}));

export const redisConfig = registerAs('redis', () => ({
  host     : process.env.REDIS_HOST || 'localhost',
  port     : process.env.REDIS_PORT || 6379,
  password : process.env.REDIS_PASSWORD,
  userName : process.env.REDIS_USER,
  userPass : process.env.REDIS_USER_PASSWORD,
}));
