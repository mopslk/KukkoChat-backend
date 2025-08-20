import { UsersModule } from '@/users/users.module';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from '@/auth/auth.service';
import { AuthController } from '@/auth/auth.controller';
import { QueriesModule } from '@/queries/queries.module';
import { AuthQuery } from '@/queries/utils/authQuery';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET_KEY,
    }),
    UsersModule,
    QueriesModule,
  ],
  controllers : [AuthController],
  providers   : [AuthService, AuthQuery],
  exports     : [
    JwtModule,
    AuthService,
  ],
})
export class AuthModule {}
