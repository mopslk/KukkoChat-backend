import {
  BadRequestException,
  Inject,
  Injectable,
  InternalServerErrorException,
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
import { decrypt, encrypt } from '@/utils/helpers/encrypt';
import { CACHE_TTL } from '@/constants/cache-ttl';
import { TwoFactorLoginDTO } from '@/auth/dto/2fa-login.dto';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    @Inject(CACHE_MANAGER) private cacheManager: CacheStore,
  ) {}

  async validateUser(userLoginDto: UserLoginDto): Promise<User> {
    const user = await this.userService.findBy('login', userLoginDto.login);
    const matchPasswords = await hashCompare(userLoginDto.password, user.password);

    if (user && matchPasswords) {
      return user;
    }
    throw new BadRequestException(ERROR_MESSAGES.INVALID_LOGIN_CREDENTIALS);
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

  async generateTemp2FAToken(userId: bigint): Promise<string> {
    const tempToken = crypto.randomUUID();
    const key = REDIS_KEYS.twoFaTempToken(tempToken);

    await this.cacheManager.set(key, userId.toString(), CACHE_TTL.minute(5));

    return tempToken;
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

  async login(user: User): Promise<AuthResponseType> {
    const tokens = await this.generateTokens(user.id);

    await this.userService.updateUserRefreshToken(user, tokens.refreshToken);

    // TODO: Переделать на fingerprint
    // await this.userService.setInfo(user, userInfo);

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

  async setupTwoFactor(userId: bigint, token: string) {
    const key = REDIS_KEYS.twoFaSecret(String(userId));
    const secret = await this.cacheManager.get<string>(key);

    if (!secret) {
      throw new BadRequestException(ERROR_MESSAGES.NOT_FOUND_2FA);
    }

    const isVerifyCode = this.verifyCode(secret, token);

    if (isVerifyCode) {
      await this.userService.setTwoFactorAuthenticationSecret(await encrypt(secret), userId);
      await this.cacheManager.del(key);
    }

    return isVerifyCode;
  }

  verifyCode(secret: string, token: string) {
    return authenticator.verify({
      token,
      secret,
    });
  }

  async generate2FaSecret(user: User) {
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

  async verify2FaForLogin(twoFactorLoginDTO: TwoFactorLoginDTO): Promise<AuthResponseType> {
    const { tempToken, code } = twoFactorLoginDTO;
    const tempTokenKey = REDIS_KEYS.twoFaTempToken(tempToken);
    const userId = await this.cacheManager.get<string | undefined>(tempTokenKey);

    if (!userId) throw new BadRequestException(ERROR_MESSAGES.INVALID_2FA_TEMP_TOKEN);

    const user = await this.userService.findBy('id', userId);

    const isValid = this.verifyCode(await decrypt(user.secret), code);

    if (!isValid) throw new BadRequestException(ERROR_MESSAGES.INVALID_2FA_CODE);

    await this.cacheManager.del(tempTokenKey);

    return this.login(user);
  }
}
