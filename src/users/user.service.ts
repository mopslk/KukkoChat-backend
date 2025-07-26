import { Injectable, UnauthorizedException } from '@nestjs/common';
import type { User } from '@prisma/client';
import { hash, hashCompare } from '@/utils/helpers/hash';
import { getTokenSignature } from '@/utils/helpers/token';
import { UserRegisterDto } from '@/users/dto/user-register.dto';
import type { RequestWithUserType } from '@/utils/types';
import type { JwtPayload } from 'jsonwebtoken';
import { convertSecondsToMs } from '@/utils/helpers/formatters';
import { UserQuery } from '@/queries/utils/userQuery';
import { ERROR_MESSAGES } from '@/constants/error-messages';

@Injectable()
export class UserService {
  constructor(
    private query: UserQuery,
  ) {}

  async findBy(property: keyof User, value: unknown): Promise<User> {
    return this.query.findBy(property, value);
  }

  async updateUserRefreshToken(user: User, refreshToken: string): Promise<void> {
    const hashedRefreshToken = await hash(getTokenSignature(refreshToken));

    await this.query.updateUserRefreshToken(user.id, hashedRefreshToken);
  }

  async setTwoFactorAuthenticationSecret(secret: string, userId: bigint): Promise<void> {
    await this.query.setTwoFactorAuthenticationSecret(secret, userId);
  }

  validateTokenTimestamp(user: User, decodedUser: JwtPayload): void {
    if (Number(user.tokens_cleared_at) > convertSecondsToMs(decodedUser.iat)) {
      throw new UnauthorizedException(ERROR_MESSAGES.TOKEN_INVALIDATED);
    }
  }

  // TODO: Переделать для проверки на fingerprint
  async checkSecurity(request: RequestWithUserType, decodedUser: JwtPayload): Promise<void> {
    const { user } = request;
    const requestInfo: PrismaJson.UserInfoType = {
      ip        : request.ip,
      userAgent : request.headers['user-agent'],
    } as const;

    this.validateTokenTimestamp(user, decodedUser);

    const promises = Object.entries(requestInfo).map(async ([key, value]) => {
      const isValid = await hashCompare(value, user.info[key]);

      if (!isValid) {
        await this.removeRefreshToken(user.id);
        throw new UnauthorizedException();
      }
    });

    await Promise.all(promises);
  }

  async removeRefreshToken(userId: bigint): Promise<void> {
    await this.query.removeRefreshToken(userId);
  }

  async createUser(data: UserRegisterDto): Promise<User> {
    const hashedPassword = await hash(data.password);

    data.setPassword(hashedPassword);
    data.removePasswordConfirmationField();

    return this.query.createUser(data);
  }

  async setInfo(user: User, userInfo: PrismaJson.UserInfoType): Promise<void> {
    await this.query.setInfo(user, userInfo);
  }
}
