import { Module, Global } from '@nestjs/common';
import { redisCacheConfig } from '@/config/cache.config';
import { CacheService } from './cache.service';

@Global()
@Module({
  providers: [
    {
      provide    : 'CACHE_INSTANCE',
      useFactory : redisCacheConfig,
    },
    CacheService,
  ],
  exports: [CacheService],
})
export class CacheModule {}
