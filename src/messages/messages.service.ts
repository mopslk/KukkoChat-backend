import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { MessageQuery } from '@/queries/utils/messageQuery';
import { getFileType, getFileUrl } from '@/utils/helpers/file';
import { CreateMessageDto } from '@/messages/dto/create-message.dto';
import { UpdateMessageDto } from '@/messages/dto/update-message.dto';
import { MessageResponseDto } from '@/messages/dto/message-response.dto';
import { instanceToPlain, plainToInstance } from 'class-transformer';
import { NotificationsService } from '@/notifications/notifications.service';
import { NotificationType } from '@/notifications/enums/events-enum';
import { ChatQuery } from '@/queries/utils/chatQuery';
import { formatChatMembers } from '@/utils/helpers/formatters';
import { encrypt } from '@/utils/helpers/encrypt';

@Injectable()
export class MessagesService {
  constructor(
    private query: MessageQuery,
    private chatQuery: ChatQuery,
    private notificationsService: NotificationsService,
  ) {}

  mapMessageAttachments(files: Express.Multer.File[]) {
    return files.map((file) => ({
      type : getFileType(file.filename),
      path : getFileUrl(file.path),
    }));
  }

  async getChatMemberIds(chatId: bigint, userId: bigint): Promise<string[]> {
    const roomMembers = await this.chatQuery.getChatMembers(chatId);

    return formatChatMembers(roomMembers, userId);
  }

  async create(createMessageDto: CreateMessageDto, files: Express.Multer.File[], userId: bigint, chatId: bigint) {
    const attachments = this.mapMessageAttachments(files);

    try {
      const message = await this.query.createMessage({
        content : await encrypt(createMessageDto.content),
        chat_id : chatId,
        user_id : userId,
      });

      const attachmentBatch = await this.query.createAttachments(attachments, message.id);
      const messageWithAttachments = attachmentBatch.count === attachments.length ? attachments : [];

      const response = plainToInstance(MessageResponseDto, MessageResponseDto.from(messageWithAttachments), {
        excludeExtraneousValues: true,
      });

      await this.notificationsService.sendSocketEvent(
        await this.getChatMemberIds(chatId, userId),
        NotificationType.NewMessage,
        instanceToPlain(response),
      );

      return response;
    } catch (error) {
      throw new InternalServerErrorException(error);
    }
  }

  async update(id: bigint, updateMessageDto: UpdateMessageDto, userId: bigint) {
    try {
      const updatedMessage = await this.query.updateMessage({
        message_id : id,
        content    : await encrypt(updateMessageDto.content),
      });

      const response = plainToInstance(MessageResponseDto, MessageResponseDto.from(updatedMessage), {
        excludeExtraneousValues: true,
      });

      await this.notificationsService.sendSocketEvent(
        await this.getChatMemberIds(updatedMessage.chat_id, userId),
        NotificationType.UpdateMessage,
        instanceToPlain(response),
      );

      return response;
    } catch (error) {
      throw new InternalServerErrorException(error);
    }
  }

  async checkUserAccessToMessage(userId: bigint, messageId: bigint) {
    return this.query.checkUserAccessToMessage(userId, messageId);
  }

  async remove(id: bigint, userId: bigint) {
    try {
      const message = await this.query.deleteMessage(id);

      await this.notificationsService.sendSocketEvent(
        await this.getChatMemberIds(message.chat_id, userId),
        NotificationType.DeleteMessage,
        { messageId: id.toString(), chatId: message.chat_id.toString() },
      );
    } catch (error) {
      throw new InternalServerErrorException(error);
    }
  }
}
