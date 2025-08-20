import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';
import { UserService } from '@/users/user.service';
import { BaseGuard } from '@/auth/guards/base.guard';
import { AuthService } from '@/auth/auth.service';

@Injectable()
export class AuthGuard extends BaseGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private userService: UserService,
    private authService: AuthService,
    jwtService: JwtService,
  ) {
    super(jwtService);
  }

  async canActivate(ctx: ExecutionContext) {
    const isPublic = this.reflector.get<boolean>('isPublic', ctx.getHandler());

    if (isPublic) {
      return true;
    }

    return this.authorize(ctx, async (userId, request, jwtUser) => {
      const forbiddenField = this.reflector.get<string>('ForbidIfUserHas', ctx.getHandler());
      const deviceId = request.header('X-DEVICE-ID');

      if (!deviceId) {
        return false;
      }

      request.user = await this.userService.findBy('id', userId);

      await this.authService.assertSessionSecurity(request, jwtUser, deviceId);

      return !(forbiddenField && request.user[forbiddenField]);
    });
  }
}
