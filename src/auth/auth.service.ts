import {
  BadRequestException,
  Injectable,
  InternalServerErrorException, UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { User } from '@prisma/client';
import { plainToInstance } from 'class-transformer';
import { UserService } from '@/users/user.service';
import { hashCompare } from '@/utils/helpers/hash';
import { getTokenSignature } from '@/utils/helpers/token';
import { UserRegisterDto } from '@/users/dto/user-register.dto';
import type {
  AuthResponseType,
  DeviceData,
  RequestWithUserType,
  SessionData,
  TokensResponseType,
} from '@/utils/types';
import { UserResponseDto } from '@/users/dto/user-response.dto';
import { UserLoginDto } from '@/auth/dto/user-login.dto';
import { authenticator } from 'otplib';
import { toDataURL } from 'qrcode';
import { convertDaysToMs, convertSecondsToMs } from '@/utils/helpers/formatters';
import { REDIS_KEYS } from '@/constants/redis-keys';
import { ERROR_MESSAGES } from '@/constants/error-messages';
import { decrypt, encrypt } from '@/utils/helpers/encrypt';
import { CACHE_TTL } from '@/constants/cache-ttl';
import { TwoFactorLoginDTO } from '@/auth/dto/2fa-login.dto';
import { CacheService } from '@/cache/cache.service';
import type { JwtPayload } from 'jsonwebtoken';
import { AuthQuery } from '@/queries/utils/authQuery';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private cacheService: CacheService,
    private query: AuthQuery,
  ) {}

  async validateUser(userLoginDto: UserLoginDto): Promise<User> {
    try {
      const user = await this.userService.findBy('login', userLoginDto.login);
      const matchPasswords = await hashCompare(userLoginDto.password, user.password);

      if (user && matchPasswords) {
        return user;
      }
    } catch (error) {
      throw new BadRequestException(ERROR_MESSAGES.AUTHENTICATE_FAILED);
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

  async generateTemp2FAToken(data: SessionData): Promise<string> {
    const tempToken = crypto.randomUUID();
    const key = REDIS_KEYS.twoFaTempToken(tempToken);
    const { userId, ...deviceData } = data;

    await this.cacheService.set(key, { userId: userId.toString(), ...deviceData }, CACHE_TTL.minute(5));

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

  async login(user: User, deviceData: DeviceData): Promise<AuthResponseType> {
    const tokens = await this.generateTokens(user.id);

    await this.userService.updateUserRefreshToken(user, tokens.refreshToken);

    await this.createSession({
      userId: user.id,
      ...deviceData,
    });

    return {
      user: plainToInstance(UserResponseDto, user),
      tokens,
    };
  }

  async register(data: UserRegisterDto): Promise<AuthResponseType> {
    try {
      const { deviceId, deviceName, ...credentials } = data;
      const user = await this.userService.createUser(plainToInstance(UserRegisterDto, credentials));

      const tokens = await this.generateTokens(user.id);

      await this.createSession({
        userId: user.id,
        deviceId,
        deviceName,
      });

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
    const secret = await this.cacheService.get<string>(key);

    if (!secret) {
      throw new BadRequestException(ERROR_MESSAGES.NOT_FOUND_2FA);
    }

    const isVerifyCode = this.verifyCode(secret, token);

    if (isVerifyCode) {
      await this.userService.setTwoFactorAuthenticationSecret(await encrypt(secret), userId);
      await this.cacheService.delete(key);
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
    let secret = await this.cacheService.get<string>(key);

    if (!secret) {
      const newSecret = authenticator.generateSecret(32);
      await this.cacheService.set(key, newSecret);

      secret = newSecret;
    }
    const otpAuthUrl = authenticator.keyuri('', '', secret);

    return toDataURL(otpAuthUrl);
  }

  async verify2FaForLogin(twoFactorLoginDTO: TwoFactorLoginDTO): Promise<AuthResponseType> {
    const { tempToken, code } = twoFactorLoginDTO;
    const tempTokenKey = REDIS_KEYS.twoFaTempToken(tempToken);
    const sessionData = await this.cacheService.get<SessionData>(tempTokenKey);
    const { userId, ...deviceData } = sessionData;

    if (!userId) throw new BadRequestException(ERROR_MESSAGES.INVALID_2FA_TEMP_TOKEN);

    const user = await this.userService.findBy('id', userId);

    const isValid = this.verifyCode(await decrypt(user.secret), code);

    if (!isValid) throw new BadRequestException(ERROR_MESSAGES.INVALID_2FA_CODE);

    await this.cacheService.delete(tempTokenKey);

    return this.login(user, deviceData);
  }

  validateTokenTimestamp(user: User, decodedUser: JwtPayload): void {
    if (Number(user.tokens_cleared_at) > convertSecondsToMs(decodedUser.iat)) {
      throw new UnauthorizedException(ERROR_MESSAGES.TOKEN_INVALIDATED);
    }
  }

  async assertSessionSecurity(request: RequestWithUserType, decodedUser: JwtPayload, deviceId: string): Promise<void> {
    const { user } = request;

    this.validateTokenTimestamp(user, decodedUser);

    const session = await this.query.getSession(user.id, deviceId);

    if (!session) {
      await this.userService.removeRefreshToken(user.id);
      throw new UnauthorizedException();
    }
  }

  async createSession(data: SessionData) {
    return this.query.createSession(data);
  }
}
