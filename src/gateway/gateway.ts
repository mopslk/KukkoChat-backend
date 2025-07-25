import {
  OnGatewayInit,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';

@WebSocketGateway()
export class AppGateway implements OnGatewayInit {
  @WebSocketServer()
    server: Server;

  constructor(
    private readonly jwtService: JwtService,
  ) {}

  afterInit(server: Server): void {
    server.use((socket: Socket, next) => {
      const token = socket.handshake.headers.authorization;

      try {
        const user = this.jwtService.verify(token);
        socket.join(user.sub);
      } catch (e) {
        next(new UnauthorizedException());
      }
      next();
    });
  }

  async sendNotification(roomId: string[] | string, event: string, data: any): Promise<void> {
    this.server.to(roomId).emit(event, await data);
  }
}
