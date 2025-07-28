import { createKeyv } from '@keyv/redis';
import { Cacheable } from 'cacheable';
import { CACHE_TTL } from '@/constants/cache-ttl';

export const redisConfig = (): Cacheable =>  {
  const primary = createKeyv({
    socket: {
      host : process.env.REDIS_HOST,
      port : Number(process.env.REDIS_PORT ?? 6379),
    },
  });
  return new Cacheable({ primary, ttl: CACHE_TTL.minute(10) });
};
