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
import { throttleConfig } from '@/config/throttle.config';
import { multerModuleConfig } from '@/config/storage.config';

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
