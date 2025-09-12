import type { ThrottlerModuleOptions } from '@nestjs/throttler';
import { CACHE_TTL } from '@/constants/cache-ttl';
import { JwtModuleOptions } from '@nestjs/jwt';
import { keysConfig } from '@/config/keys.config';

export const jwtConfig: JwtModuleOptions = {
  secret: keysConfig().jwtSecret,
};

export const throttleConfig: ThrottlerModuleOptions = {
  throttlers: [
    {
      ttl   : CACHE_TTL.minute(1),
      limit : 100,
    },
  ],
};
