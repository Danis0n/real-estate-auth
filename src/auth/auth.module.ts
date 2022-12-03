import { Module } from '@nestjs/common';
import { AuthService } from './service/auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfirmationToken } from './entity/confirmation.token.entity';
import { RefreshToken } from './entity/refresh.token.entity';
import { PasswordToken } from './entity/password.token.entity';
import { ConfirmationTokenRepository } from './repository/confirmation.token.repository';
import { RefreshTokenRepository } from './repository/refresh.token.repository';
import { PasswordTokenRepository } from './repository/password.token.repository';
import { AuthUtil } from './util/auth.util';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { USER_PACKAGE_NAME, USER_SERVICE_NAME } from './proto/user.pb';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    ConfirmationTokenRepository,
    RefreshTokenRepository,
    PasswordTokenRepository,
    AuthUtil,
  ],
  imports: [
    TypeOrmModule.forFeature([ConfirmationToken, RefreshToken, PasswordToken]),
    ClientsModule.register([
      {
        name: USER_SERVICE_NAME,
        transport: Transport.GRPC,
        options: {
          url: '0.0.0.0:50052',
          package: USER_PACKAGE_NAME,
          protoPath: 'node_modules/proto-config/proto/user.proto',
        },
      },
    ]),
  ],
})
export class AuthModule {}
