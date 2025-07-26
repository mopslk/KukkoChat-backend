import {
  Injectable, InternalServerErrorException, UnauthorizedException,
} from '@nestjs/common';
import { CreateChatDto } from '@/chats/dto/create-chat.dto';
import { UpdateChatDto } from '@/chats/dto/update-chat.dto';
import { ChatQuery } from '@/queries/utils/chatQuery';
import { MessageQuery } from '@/queries/utils/messageQuery';
import { ChatListResponseDto } from '@/chats/dto/chat-list-response.dto';
import { instanceToPlain, plainToInstance } from 'class-transformer';
import { ChatType, Role, type User } from '@prisma/client';
import type { ChatMembersCreateInput } from '@/utils/types';
import { ChatResponseDto } from '@/chats/dto/chat-response.dto';
import { NotificationType } from '@/notifications/enums/events-enum';
import { NotificationsService } from '@/notifications/notifications.service';
import { formatChatMembers } from '@/utils/helpers/formatters';
import { ERROR_MESSAGES } from '@/constants/error-messages';

@Injectable()
export class ChatsService {
  constructor(
    private query: ChatQuery,
    private messageQuery: MessageQuery,
    private notificationsService: NotificationsService,
  ) {}

  async create(createChatDto: CreateChatDto, user: User) {
    const { name, type } = createChatDto;

    const chat = await this.query.createChat(type, name);

    if (!chat) {
      throw new InternalServerErrorException(ERROR_MESSAGES.FAILED_CHAT_CREATE);
    }

    const chatMembers: ChatMembersCreateInput[] = [
      { user_id: user.id, chat_id: chat.id, role: chat.type === ChatType.group ? Role.owner : null },
      ...createChatDto.receiverIds.reduce<ChatMembersCreateInput[]>((acc, receiverId) => ([
        ...acc,
        { user_id: receiverId, chat_id: chat.id, role: chat.type === ChatType.group ? Role.member : null },
      ]), []),
    ];

    await this.query.addMembersToChat(chatMembers);

    if (createChatDto.message) {
      const message = await this.messageQuery.createMessage({
        user_id : user.id,
        chat_id : chat.id,
        content : createChatDto.message,
      });

      await this.query.updateChat(chat.id, createChatDto, message.id);
    }

    const createdChat = await this.query.getChat(chat.id);

    const response = plainToInstance(ChatResponseDto, ChatResponseDto.from(createdChat));

    const roomMembers = await this.query.getChatMembers(createdChat.id);

    const chatMemberIds = formatChatMembers(roomMembers, user.id);

    await this.notificationsService.sendSocketEvent(
      chatMemberIds,
      NotificationType.NewChat,
      instanceToPlain(response),
    );

    return response;
  }

  async findAll(userId: bigint): Promise<ChatListResponseDto[]> {
    const userChats = await this.query.getUserChats(userId);

    const mappedChats = userChats.map(({ chat }) => chat);
    return plainToInstance(ChatListResponseDto, mappedChats);
  }

  async findOne(id: bigint) {
    const chat = await this.query.getChat(id);

    return plainToInstance(ChatResponseDto, ChatResponseDto.from(chat));
  }

  async update(id: bigint, updateChatDto: UpdateChatDto, userId: bigint) {
    const chat = await this.query.getChat(id);

    if (chat.type !== ChatType.group) {
      throw new InternalServerErrorException(ERROR_MESSAGES.PRIVATE_CHAT_UPDATE);
    }

    const updatedChat = await this.query.updateChat(id, updateChatDto);

    const response = plainToInstance(ChatResponseDto, ChatResponseDto.from(updatedChat));

    const roomMembers = await this.query.getChatMembers(chat.id);

    const chatMemberIds = formatChatMembers(roomMembers, userId);

    await this.notificationsService.sendSocketEvent(
      chatMemberIds,
      NotificationType.UpdateChat,
      instanceToPlain(response),
    );

    return response;
  }

  async remove(chatId: bigint, userId: bigint) {
    const userAccess = await this.query.getUserAccessInChat(userId, chatId);

    if (userAccess.role && userAccess.role !== Role.owner) {
      throw new UnauthorizedException();
    }

    await this.query.removeChat(chatId);

    const roomMembers = await this.query.getChatMembers(chatId);

    const chatMemberIds = formatChatMembers(roomMembers, userId);

    await this.notificationsService.sendSocketEvent(
      chatMemberIds,
      NotificationType.RemoveChat,
      { chatId: chatId.toString() },
    );
  }

  async checkUserAccessToChat(userId: bigint, chatId: bigint) {
    const memberRow = await this.query.getUserAccessInChat(userId, chatId);

    return memberRow !== null;
  }
}
