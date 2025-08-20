import type { Request } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import type { RequestWithUserType } from '@/utils/types';
import type { JwtService } from '@nestjs/jwt';
import { type ExecutionContext, UnauthorizedException } from '@nestjs/common';

export class BaseGuard {
  constructor(protected readonly jwtService: JwtService) {}

  protected extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  private async authenticate(token?: string): Promise<JwtPayload> {
    try {
      return await this.jwtService.verifyAsync<JwtPayload>(token, { secret: process.env.JWT_SECRET });
    } catch {
      throw new UnauthorizedException();
    }
  }

  protected async authorize(
    ctx: ExecutionContext,
    accessCheck: (userId: string | number, request: RequestWithUserType, user: JwtPayload) => Promise<boolean>,
  ): Promise<boolean> {
    const request = ctx.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromHeader(request);
    const user = await this.authenticate(token);

    return accessCheck(user.sub, request, user);
  }
}
