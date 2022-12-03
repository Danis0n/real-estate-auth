import { HttpStatus, Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfirmationTokenRepository } from '../repository/confirmation.token.repository';
import { LoginRequestDto, RegisterRequestDto } from '../dto/auth.user.dto';
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
import { AuthRequest } from "../proto/auth.pb";

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
    const candidate = await this.checkData(dto);
    if (candidate)
      return { error: [candidate], status: HttpStatus.BAD_REQUEST };

    dto.password = await bcrypt.hash(dto.password, 5);
    const response: CreateUserResponse = await firstValueFrom(
      this.userSvc.create(dto),
    );
    return { error: ['none'], status: 200 };
  }

  public async login(dto: LoginRequestDto) {
    return undefined;
  }

  public async auth(req) {
    return undefined;
  }

  private async checkData(dto: RegisterRequestDto): Promise<string> {
    if (
      !!(await firstValueFrom(this.userSvc.findByLogin({ login: dto.login })))
        .user
    )
      return 'Пользователь с таким логином уже существует';
    if (
      !!(await firstValueFrom(this.userSvc.findByPhone({ phone: dto.phone })))
        .user
    )
      return 'Пользователь с таким телефоном уже существует';
    if (
      !!(await firstValueFrom(this.userSvc.findByEmail({ email: dto.email })))
        .user
    )
      return 'Пользователь с такой эл. почтой уже существует';
    if (!!(await firstValueFrom(this.userSvc.findByInn({ inn: dto.inn }))).user)
      return 'Пользователь с таким инн уже существует';
    return null;
  }
}
