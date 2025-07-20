import { Injectable } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import type { AttachmentCreateInput, MessageCreateInput, MessageUpdateInput } from '@/utils/types';
import { type Message, type MessageAttachments, Prisma } from '@prisma/client';

@Injectable()
export class MessageQuery {
  constructor(private prisma: PrismaService) {}

  async createMessage(messageCreateInput: MessageCreateInput): Promise<Message> {
    return this.prisma.message.create({
      data: messageCreateInput,
    });
  }

  async createAttachments(attachments: AttachmentCreateInput[], messageId: bigint): Promise<Prisma.BatchPayload> {
    return this.prisma.messageAttachments.createMany({
      data: attachments.reduce<MessageAttachments[]>((acc, attachment) => ([
        ...acc,
        {
          ...attachment,
          message_id: messageId,
        },
      ]), []),
    });
  }

  async updateMessage(messageUpdateInput: MessageUpdateInput) {
    return this.prisma.message.update({
      where: {
        id: messageUpdateInput.message_id,
      },
      data: {
        content: messageUpdateInput.content,
      },
    });
  }

  async checkUserAccessToMessage(userId: bigint, messageId: bigint) {
    const messageRow = await this.prisma.message.findFirst({
      where: {
        user_id : userId,
        id      : messageId,
      },
    });

    return messageRow !== null;
  }

  async deleteMessage(messageId: bigint) {
    return this.prisma.message.delete({
      where: {
        id: messageId,
      },
    });
  }
}
