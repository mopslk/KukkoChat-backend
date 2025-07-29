import type { ThrottlerModuleOptions } from '@nestjs/throttler';
import { CACHE_TTL } from '@/constants/cache-ttl';

export const throttleConfig: ThrottlerModuleOptions = {
  throttlers: [
    {
      ttl   : CACHE_TTL.minute(1),
      limit : 100,
    },
  ],
};
