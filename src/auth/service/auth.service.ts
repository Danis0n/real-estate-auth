import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfirmationTokenRepository } from '../repository/confirmation.token.repository';
import { RegisterRequestDto } from '../dto/auth.user.dto';
import {
  CreateUserResponse,
  USER_SERVICE_NAME,
  UserServiceClient,
} from '../proto/user.pb';
import { ClientGrpc } from '@nestjs/microservices';
import { PasswordTokenRepository } from '../repository/password.token.repository';
import { RefreshTokenRepository } from '../repository/refresh.token.repository';
import { firstValueFrom } from 'rxjs';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService implements OnModuleInit {
  private userSvc: UserServiceClient;

  @Inject(USER_SERVICE_NAME)
  private readonly client: ClientGrpc;

  @Inject(ConfirmationTokenRepository)
  public readonly confirmationTokenRepo: ConfirmationTokenRepository;

  @Inject(PasswordTokenRepository)
  public readonly passwordTokenRepo: PasswordTokenRepository;

  @Inject(RefreshTokenRepository)
  public readonly refreshTokenRepo: RefreshTokenRepository;

  onModuleInit(): void {
    this.userSvc = this.client.getService<UserServiceClient>(USER_SERVICE_NAME);
  }

  public async register(dto: RegisterRequestDto) {
    dto.password = await bcrypt.hash(dto.password, 5);
    const response: CreateUserResponse = await firstValueFrom(
      dto.inn == '' && dto.link == ''
        ? this.userSvc.create(dto)
        : this.userSvc.createUr(dto),
    );

    return { error: ['none'], status: 200 };
  }

  login(payload) {
    return undefined;
  }

  auth(payload) {
    return undefined;
  }

  registerUr(payload) {
    return undefined;
  }
}
