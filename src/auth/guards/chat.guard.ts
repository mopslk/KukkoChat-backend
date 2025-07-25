import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ChatsService } from '@/chats/chats.service';
import { BaseGuard } from '@/auth/guards/base.guard';

@Injectable()
export class ChatGuard extends BaseGuard implements CanActivate {
  constructor(
    private chatService: ChatsService,
    jwtService: JwtService,
  ) {
    super(jwtService);
  }

  async canActivate(ctx: ExecutionContext) {
    return this.authorize(ctx, async (userId, request) => this.chatService.checkUserAccessToChat(BigInt(userId), BigInt(request.params.id)));
  }
}
