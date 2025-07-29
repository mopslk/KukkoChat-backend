import {
  Body, Controller, Get, Post, Query,
} from '@nestjs/common';
import type { AuthResponseType } from '@/utils/types';
import { AuthService } from '@/auth/auth.service';
import { Public } from '@/utils/decorators/public.decorator';
import { RefreshDto } from '@/auth/dto/refresh.dto';
import { UserRegisterDto } from '@/users/dto/user-register.dto';
import { UserLoginDto } from '@/auth/dto/user-login.dto';
import { CurrentUser } from '@/utils/decorators/current-user.decorator';
import type { User } from '@prisma/client';
import { ForbidIfUserHas } from '@/utils/decorators/forbid-user.decorator';
import { TwoFactorLoginDTO } from '@/auth/dto/2fa-login.dto';
import { Throttle } from '@nestjs/throttler';
import { CACHE_TTL } from '@/constants/cache-ttl';

@Throttle({ default: { ttl: CACHE_TTL.minute(1), limit: 5 } })
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
  ) {}

  @Public()
  @Post('login')
  async login(@Body() userLoginDto: UserLoginDto) {
    const user = await this.authService.validateUser(userLoginDto);

    if (user.secret) {
      const tempToken = await this.authService.generateTemp2FAToken(user.id);
      return { need2fa: true, tempToken };
    }

    return this.authService.login(user);
  }

  @Public()
  @Post('2fa/verify-code')
  async verify2faForLogin(@Body() twoFactorLoginDTO: TwoFactorLoginDTO): Promise<AuthResponseType> {
    return this.authService.verify2FaForLogin(twoFactorLoginDTO);
  }

  @Public()
  @Throttle({ default: { ttl: CACHE_TTL.minute(1), limit: 10 } })
  @Post('refresh')
  async refresh(@Body() refreshDto: RefreshDto) {
    return this.authService.refresh(refreshDto.refreshToken);
  }

  @Public()
  @Throttle({ default: { ttl: CACHE_TTL.hour(1), limit: 5 } })
  @Post('register')
  async register(@Body() credentials: UserRegisterDto): Promise<AuthResponseType> {
    return this.authService.register(credentials);
  }

  @ForbidIfUserHas('secret')
  @Get('2fa/generate-secret')
  async generateCode(@CurrentUser() user: User) {
    return this.authService.generate2FaSecret(user);
  }

  @ForbidIfUserHas('secret')
  @Get('2fa/setup')
  async setup2Fa(@CurrentUser() user: User, @Query('code') code: string) {
    return this.authService.setupTwoFactor(user.id, code);
  }
}
