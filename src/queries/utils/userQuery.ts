import { Injectable } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { Prisma, User } from '@prisma/client';
import { hash } from '@/utils/helpers/hash';

@Injectable()
export class UserQuery {
  constructor(
    private prisma: PrismaService,
  ) {}

  async findBy(property: keyof User, value: unknown) {
    return this.prisma.user.findFirst({
      where: {
        [property]: value,
      },
    });
  }

  async updateUserRefreshToken(userId: bigint, refreshToken: string): Promise<void> {
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        refresh_token: refreshToken,
      },
    });
  }

  async setTwoFactorAuthenticationSecret(secret: string, userId: bigint): Promise<void> {
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        secret,
      },
    });
  }

  async removeRefreshToken(userId: bigint): Promise<void> {
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        refresh_token     : null,
        tokens_cleared_at : String(Date.now()),
      },
    });
  }

  async createUser(data: Prisma.UserCreateInput) {
    return this.prisma.user.create({
      data,
    });
  }

  async setInfo(user: User, userInfo: PrismaJson.UserInfoType) {
    this.prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        info: {
          ip        : await hash(userInfo.ip),
          userAgent : await hash(userInfo.userAgent),
        },
      },
    });
  }
}
