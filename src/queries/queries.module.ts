import { Module } from '@nestjs/common';
import { MessageQuery } from '@/queries/utils/messageQuery';
import { ChatQuery } from '@/queries/utils/chatQuery';
import { AuthQuery } from '@/queries/utils/authQuery';

@Module({
  providers: [MessageQuery, ChatQuery, AuthQuery],
})
export class QueriesModule {}
