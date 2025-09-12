import { createKeyv } from '@keyv/redis';
import { Cacheable } from 'cacheable';
import { CACHE_TTL } from '@/constants/cache-ttl';
import { redisConfig } from '@/config/database.config';

export const redisCacheConfig = (): Cacheable =>  {
  const redis = redisConfig();
  const primary = createKeyv({
    socket: {
      host : redis.host,
      port : Number(redis.port),
    },
  });
  return new Cacheable({ primary, ttl: CACHE_TTL.minute(10) });
};
