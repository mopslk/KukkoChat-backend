import {
  Controller, Post, Body, Patch, Param, Delete, UseInterceptors, UploadedFiles, UseGuards,
} from '@nestjs/common';
import { FilesInterceptor } from '@nestjs/platform-express';
import { MessagesService } from '@/messages/messages.service';
import { CreateMessageDto } from '@/messages/dto/create-message.dto';
import { UpdateMessageDto } from '@/messages/dto/update-message.dto';
import { multerConfig } from '@/config/storage.config';
import { ChatGuard } from '@/auth/guards/chat.guard';
import { CurrentUser } from '@/utils/decorators/current-user.decorator';
import { User } from '@prisma/client';
import { MessageGuard } from '@/auth/guards/message.guard';

@Controller('messages')
export class MessagesController {
  constructor(
    private readonly messagesService: MessagesService,
  ) {}

  @UseGuards(ChatGuard)
  @Post(':id')
  @UseInterceptors(FilesInterceptor('attachments', 10, multerConfig))
  async create(
  @CurrentUser() user: User,
    @UploadedFiles() files: Express.Multer.File[],
    @Body() createMessageDto: CreateMessageDto,
    @Param('id') chatId: string,
  ) {
    return this.messagesService.create(createMessageDto, files, user.id, BigInt(chatId));
  }

  @UseGuards(MessageGuard)
  @Patch(':id')
  async update(@Param('id') id: string, @Body() updateMessageDto: UpdateMessageDto, @CurrentUser() user: User) {
    return this.messagesService.update(BigInt(id), updateMessageDto, user.id);
  }

  @UseGuards(MessageGuard)
  @Delete(':id')
  async remove(@Param('id') id: string, @CurrentUser() user: User) {
    return this.messagesService.remove(BigInt(id), user.id);
  }
}
