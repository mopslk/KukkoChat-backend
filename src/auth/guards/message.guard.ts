import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { MessagesService } from '@/messages/messages.service';
import { BaseGuard } from '@/auth/guards/base.guard';

@Injectable()
export class MessageGuard extends BaseGuard implements CanActivate {
  constructor(
    private messageService: MessagesService,
    jwtService: JwtService,
  ) {
    super(jwtService);
  }

  async canActivate(ctx: ExecutionContext) {
    return this.authorize(ctx, async (userId, request) => this.messageService.checkUserAccessToMessage(BigInt(userId), BigInt(request.params.id)));
  }
}
