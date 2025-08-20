import { PrismaService } from '@/prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import { SessionData } from '@/utils/types';

@Injectable()
export class AuthQuery {
  constructor(
    private prisma: PrismaService,
  ) {}

  async createSession(data: SessionData) {
    return this.prisma.session.upsert({
      where: {
        user_id_device_id: {
          user_id   : data.userId,
          device_id : data.deviceId,
        },
      },
      update : {},
      create : {
        user_id     : data.userId,
        device_id   : data.deviceId,
        device_name : data.deviceName,
      },
    });
  }

  async getSession(userId: bigint, deviceId: string) {
    return this.prisma.session.findFirst({
      where: {
        user_id   : userId,
        device_id : deviceId,
      },
    });
  }

  async getSessions(userId: bigint) {
    return this.prisma.session.findMany({
      where: {
        user_id: userId,
      },
      select: {
        device_name: true,
      },
    });
  }
}
