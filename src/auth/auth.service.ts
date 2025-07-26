import {
  BadRequestException,
  Inject,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { User } from '@prisma/client';
import { plainToInstance } from 'class-transformer';
import { UserService } from '@/users/user.service';
import { hashCompare } from '@/utils/helpers/hash';
import { getTokenSignature } from '@/utils/helpers/token';
import { UserRegisterDto } from '@/users/dto/user-register.dto';
import type { AuthResponseType, TokensResponseType } from '@/utils/types';
import { UserResponseDto } from '@/users/dto/user-response.dto';
import { UserLoginDto } from '@/auth/dto/user-login.dto';
import { authenticator } from 'otplib';
import { toDataURL } from 'qrcode';
import { CACHE_MANAGER, type CacheStore } from '@nestjs/cache-manager';
import { convertDaysToMs, convertSecondsToMs } from '@/utils/helpers/formatters';
import { REDIS_KEYS } from '@/constants/redis-keys';
import { ERROR_MESSAGES } from '@/constants/error-messages';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    @Inject(CACHE_MANAGER) private cacheManager: CacheStore,
  ) {}

  async validateUser(userLoginDto: UserLoginDto): Promise<User | null> {
    const user = await this.userService.findBy('login', userLoginDto.login);
    const matchPasswords = await hashCompare(userLoginDto.password, user.password);

    if (user && matchPasswords) {
      return user;
    }
    return null;
  }

  async generateTokens(userId: bigint, onlyAccessToken?: boolean): Promise<TokensResponseType> {
    const payload = { sub: userId.toString() };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret    : process.env.JWT_SECRET_KEY,
      expiresIn : '30m',
    });

    if (onlyAccessToken) {
      return { accessToken };
    }

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret    : process.env.JWT_REFRESH_SECRET_KEY,
      expiresIn : '7d',
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  async refresh(refreshToken: string): Promise<TokensResponseType> {
    const userDataFromToken = await this.jwtService.verifyAsync(refreshToken, {
      secret: process.env.JWT_REFRESH_SECRET_KEY,
    });

    const user = await this.userService.findBy('id', BigInt(userDataFromToken.sub));

    const compareHashTokens = await hashCompare(getTokenSignature(refreshToken), user.refresh_token);

    if (!user || !compareHashTokens) {
      throw new BadRequestException(ERROR_MESSAGES.INVALID_REFRESH_TOKEN);
    }

    if (convertSecondsToMs(Number(userDataFromToken.exp)) - Date.now() <= convertDaysToMs(1)) {
      const tokens = await this.generateTokens(user.id);
      await this.userService.updateUserRefreshToken(user, tokens.refreshToken);

      return tokens;
    }

    const { accessToken } = await this.generateTokens(user.id, true);

    return {
      refreshToken,
      accessToken,
    };
  }

  async login(user: User, userInfo: PrismaJson.UserInfoType): Promise<AuthResponseType> {
    const tokens = await this.generateTokens(user.id);

    await this.userService.updateUserRefreshToken(user, tokens.refreshToken);

    await this.userService.setInfo(user, userInfo);

    return {
      user: plainToInstance(UserResponseDto, user),
      tokens,
    };
  }

  async register(credentials: UserRegisterDto): Promise<AuthResponseType> {
    try {
      const user = await this.userService.createUser(credentials);

      const tokens = await this.generateTokens(user.id);

      await this.userService.updateUserRefreshToken(user, tokens.refreshToken);

      return {
        user: plainToInstance(UserResponseDto, user),
        tokens,
      };
    } catch (e) {
      throw new InternalServerErrorException(e);
    }
  }

  async verifyCodeForSetupTwoFactor(userId: bigint, token: string) {
    const key = REDIS_KEYS.twoFaSecret(String(userId));
    const secret = await this.cacheManager.get<string>(key);

    if (!secret) {
      throw new BadRequestException(ERROR_MESSAGES.NOT_FOUND_2FA);
    }

    const isVerifyCode = authenticator.verify({
      token,
      secret,
    });

    if (isVerifyCode) {
      await this.userService.setTwoFactorAuthenticationSecret(secret, userId);
      await this.cacheManager.del(key);
    }

    return isVerifyCode;
  }

  async verifyCode(secret: string, token: string) {
    return authenticator.verify({
      token,
      secret,
    });
  }

  async generateCode(user: User) {
    const key = REDIS_KEYS.twoFaSecret(String(user.id));
    let secret = await this.cacheManager.get<string>(key);

    if (!secret) {
      const newSecret = authenticator.generateSecret(32);
      await this.cacheManager.set(key, newSecret);

      secret = newSecret;
    }
    const otpAuthUrl = authenticator.keyuri('', '', secret);

    return toDataURL(otpAuthUrl);
  }

  async checkingForTwoFactor(user: User, code?: string): Promise<void> {
    if (user.secret && !code) {
      throw new UnauthorizedException('2fa');
    }

    if (user.secret && code) {
      const check2fa = await this.verifyCode(user.secret, code);

      if (!check2fa) {
        throw new BadRequestException(ERROR_MESSAGES.INVALID_2FA_CODE);
      }
    }
  }
}
