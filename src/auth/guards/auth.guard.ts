import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';
import { UserService } from '@/users/user.service';
import { BaseGuard } from '@/auth/guards/base.guard';

@Injectable()
export class AuthGuard extends BaseGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private userService: UserService,
    jwtService: JwtService,
  ) {
    super(jwtService);
  }

  async canActivate(ctx: ExecutionContext) {
    const isPublic = this.reflector.get<boolean>('isPublic', ctx.getHandler());

    if (isPublic) {
      return true;
    }

    return this.authorize(ctx, async (userId, request) => {
      const forbiddenField = this.reflector.get<string>('ForbidIfUserHas', ctx.getHandler());

      request.user = await this.userService.findBy('id', userId);

      return !(forbiddenField && request.user[forbiddenField]);
    });
  }
}
