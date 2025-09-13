import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from '@/auth/guards/auth.guard';
import { UniqueConstraint } from '@/utils/decorators/unique.decorator';
import { PrismaModule } from '@/prisma/prisma.module';
import { AuthModule } from '@/auth/auth.module';
import { UsersModule } from '@/users/users.module';
import { MulterModule } from '@nestjs/platform-express';
import { ChatsModule } from '@/chats/chats.module';
import { MessagesModule } from '@/messages/messages.module';
import { FilesModule } from '@/files/files.module';
import { GatewayModule } from '@/gateway/gateway.module';
import { NotificationsModule } from '@/notifications/notifications.module';
import { CacheModule } from '@/cache/cache.module';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { multerModuleConfig } from '@/config/storage.config';
import { filesConfig } from '@/config/files.config';
import { ConfigModule } from '@nestjs/config';
import { postgresConfig, redisConfig } from '@/config/database.config';
import { keysConfig } from '@/config/keys.config';
import { throttleConfig } from '@/config/auth.config';

@Module({
  imports: [
    UsersModule,
    AuthModule,
    PrismaModule,
    ChatsModule,
    MulterModule.register(multerModuleConfig),
    MessagesModule,
    FilesModule,
    GatewayModule,
    NotificationsModule,
    CacheModule,
    ThrottlerModule.forRoot(throttleConfig),
    ConfigModule.forRoot({
      load     : [postgresConfig, redisConfig, keysConfig, filesConfig],
      isGlobal : true,
    }),
  ],
  controllers : [],
  providers   : [
    {
      provide  : APP_GUARD,
      useClass : AuthGuard,
    },
    {
      provide  : APP_GUARD,
      useClass : ThrottlerGuard,
    },
    UniqueConstraint,
  ],
})
export class AppModule {}
