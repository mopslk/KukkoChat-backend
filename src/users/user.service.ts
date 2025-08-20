import { Injectable } from '@nestjs/common';
import type { User } from '@prisma/client';
import { hash } from '@/utils/helpers/hash';
import { getTokenSignature } from '@/utils/helpers/token';
import { UserRegisterDto } from '@/users/dto/user-register.dto';
import { UserQuery } from '@/queries/utils/userQuery';

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

  async removeRefreshToken(userId: bigint): Promise<void> {
    await this.query.removeRefreshToken(userId);
  }

  async createUser(data: UserRegisterDto): Promise<User> {
    const hashedPassword = await hash(data.password);

    data.setPassword(hashedPassword);
    data.removePasswordConfirmationField();

    return this.query.createUser(data);
  }
}
