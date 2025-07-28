import { Module, Global } from '@nestjs/common';
import { redisConfig } from '@/config/cache.config';
import { CacheService } from './cache.service';

@Global()
@Module({
  providers: [
    {
      provide    : 'CACHE_INSTANCE',
      useFactory : redisConfig,
    },
    CacheService,
  ],
  exports: [CacheService],
})
export class CacheModule {}
