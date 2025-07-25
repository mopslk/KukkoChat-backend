import {
  BadRequestException, Body, Controller, Get, Ip, Headers, Post, Query,
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

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
  ) {}

  @Public()
  @Post('login')
  async login(
  @Body() userLoginDto: UserLoginDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    const user = await this.authService.validateUser(userLoginDto);

    if (!user) {
      throw new BadRequestException('Invalid login or password!');
    }

    await this.authService.checkingForTwoFactor(user, userLoginDto?.code);

    return this.authService.login(user, { ip, userAgent });
  }

  @Public()
  @Post('refresh')
  async refresh(@Body() refreshDto: RefreshDto) {
    return this.authService.refresh(refreshDto.refreshToken);
  }

  @Post('register')
  @Public()
  async register(@Body() credentials: UserRegisterDto): Promise<AuthResponseType> {
    return this.authService.register(credentials);
  }

  @Get('2fa/generate-code')
  @ForbidIfUserHas('secret')
  async generateCode(@CurrentUser() user: User) {
    return this.authService.generateCode(user);
  }

  @Get('2fa/verify-code')
  @ForbidIfUserHas('secret')
  async verifyCode(@CurrentUser() user: User, @Query('code') code: string) {
    return this.authService.verifyCodeForSetupTwoFactor(user.id, code);
  }
}
