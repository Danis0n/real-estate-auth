import { HttpStatus, Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ConfirmationTokenRepository } from '../repository/confirmation.token.repository';
import {
  AuthResponseDto,
  LoginRequestDto,
  LoginResponseDto,
  LogoutRequestDto,
  LogoutResponseDto,
  RegisterRequestDto,
  ValidateRequestDto,
} from '../dto/auth.user.dto';
import {
  CheckUserResponse,
  ConfirmAccountResponse,
  CreateUserResponse,
  FindOneUserResponse,
  GetHashedPasswordResponse,
  USER_SERVICE_NAME,
  UserServiceClient,
} from '../proto/user.pb';
import { ClientGrpc } from '@nestjs/microservices';
import { PasswordTokenRepository } from '../repository/password.token.repository';
import { RefreshTokenRepository } from '../repository/refresh.token.repository';
import { firstValueFrom } from 'rxjs';
import * as bcrypt from 'bcryptjs';
import { UserDto } from '../dto/user.dto';
import { JwtService } from './jwt.service';
import { RefreshTokenMapper } from '../mapper/refresh.token.mapper';
import { RoleMapper } from '../mapper/role.mapper';
import { AtJwtPayload } from '../dto/jwt.dto';
import {
  AuthRequest,
  ConfirmRequest,
  ConfirmResponse,
  RedirectRequest,
  RedirectResponse,
  RegisterResponse,
  RestorePasswordRequest,
  RestorePasswordResponse,
  UpdatePasswordRequest,
  UpdatePasswordResponse,
  ValidateResponse,
} from '../proto/auth.pb';
import { RefreshToken } from '../entity/refresh.token.entity';
import { PasswordToken } from '../entity/password.token.entity';
import { v4 as uuidv4 } from 'uuid';
import {
  EMAIL_SERVICE_NAME,
  EmailServiceClient,
  PasswordRestoreResponse,
} from '../proto/email.pb';
import { ConfirmationToken } from '../entity/confirmation.token.entity';
import {
  CONFIRMATION_TOKEN_LIVE_TIME,
  RESTORE_TOKEN_LIVE_TIME,
} from '../config/auth-constants';

@Injectable()
export class AuthService implements OnModuleInit {
  private userSvc: UserServiceClient;
  private emailSvc: EmailServiceClient;

  @Inject(USER_SERVICE_NAME)
  private readonly userClient: ClientGrpc;

  @Inject(EMAIL_SERVICE_NAME)
  private readonly emailClient: ClientGrpc;

  @Inject(JwtService)
  private readonly jwtService: JwtService;

  @Inject(RoleMapper)
  private readonly roleMapper: RoleMapper;

  @Inject(RefreshTokenMapper)
  private readonly refreshTokenMapper: RefreshTokenMapper;

  @Inject(ConfirmationTokenRepository)
  public readonly confirmationTokenRepo: ConfirmationTokenRepository;

  @Inject(PasswordTokenRepository)
  public readonly passwordTokenRepo: PasswordTokenRepository;

  @Inject(RefreshTokenRepository)
  public readonly refreshTokenRepo: RefreshTokenRepository;

  onModuleInit(): void {
    this.userSvc =
      this.userClient.getService<UserServiceClient>(USER_SERVICE_NAME);
    this.emailSvc =
      this.emailClient.getService<EmailServiceClient>(EMAIL_SERVICE_NAME);
  }

  public async register(dto: RegisterRequestDto): Promise<RegisterResponse> {
    const candidate: CheckUserResponse = await firstValueFrom(
      this.userSvc.checkUser({
        email: dto.email,
        login: dto.login,
        phone: dto.phone,
      }),
    );

    if (candidate.status == HttpStatus.BAD_REQUEST)
      return { error: candidate.error, status: HttpStatus.BAD_REQUEST };

    dto.password = await bcrypt.hash(dto.password, 5);
    const response: CreateUserResponse = await firstValueFrom(
      this.userSvc.create(dto),
    );

    if (response.user == null || response.status != HttpStatus.OK)
      return {
        error: 'Ошибка создания',
        status: HttpStatus.BAD_REQUEST,
      };

    const confirmationToken: ConfirmationToken = new ConfirmationToken();
    confirmationToken.token = uuidv4();
    confirmationToken.createdAt = new Date();
    confirmationToken.expiresAt = new Date(
      confirmationToken.createdAt.getTime() + CONFIRMATION_TOKEN_LIVE_TIME,
    );

    confirmationToken.userId = response.user.id;
    await this.confirmationTokenRepo.saveToken(confirmationToken);

    return await firstValueFrom(
      this.emailSvc.accountConfirm({
        token: confirmationToken.token,
        email: response.user.email,
      }),
    );
  }

  public async login(dto: LoginRequestDto): Promise<LoginResponseDto> {
    const response: FindOneUserResponse = await firstValueFrom(
      this.userSvc.findByLogin({
        login: dto.login,
      }),
    );
    const user: UserDto = response.user;

    if (user && (await this.validatePassword(dto)) && !user.userInfo.locked) {
      await this.refreshTokenRepo.deleteTokensByUser(user.id);

      const tokens: { accessToken; refreshToken } =
        await this.jwtService.generateTokens(user);

      return {
        user: user,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        error: null,
        status: HttpStatus.OK,
      };
    }
    return {
      user: null,
      accessToken: null,
      refreshToken: null,
      error: 'Неверный пароль или логин',
      status: HttpStatus.UNAUTHORIZED,
    };
  }

  public async refresh(dto: AuthRequest): Promise<AuthResponseDto> {
    const token: RefreshToken = await this.refreshTokenRepo.findByTokenValue(
      dto.refreshToken,
    );
    if (token == null)
      return {
        user: null,
        accessToken: null,
        refreshToken: null,
        error: 'Токен не существует',
      };

    if (
      this.jwtService.verifyToken(dto.refreshToken) !== null &&
      dto.refreshToken === token.token
    ) {
      const userId: string = this.jwtService.decodeRToken(dto.refreshToken).id;

      const response: FindOneUserResponse = await firstValueFrom(
        this.userSvc.findById({ id: userId }),
      );
      if (response.user.userInfo.locked) {
        return {
          user: null,
          accessToken: null,
          refreshToken: null,
          error: 'Пользователь заблокирован!',
        };
      }

      await this.refreshTokenRepo.deleteTokensByUser(response.user.id);

      const tokens: { accessToken; refreshToken } =
        await this.jwtService.generateTokens(response.user);

      return {
        user: response.user,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        error: null,
      };
    }
    return { accessToken: null, error: null, refreshToken: null, user: null };
  }

  public async logout(dto: LogoutRequestDto): Promise<LogoutResponseDto> {
    const decoded: AtJwtPayload = this.jwtService.decodeAToken(dto.accessToken);
    await this.refreshTokenRepo.deleteTokensByUser(decoded.id);
    return { status: 200 };
  }

  public async validate(dto: ValidateRequestDto): Promise<ValidateResponse> {
    const result: AtJwtPayload = await this.jwtService.verifyToken(dto.token);

    return !!result
      ? {
          status: HttpStatus.OK,
          error: null,
        }
      : {
          status: HttpStatus.UNAUTHORIZED,
          error: 'Не авторизован',
        };
  }

  public async restorePassword(
    dto: RestorePasswordRequest,
  ): Promise<RestorePasswordResponse> {
    const potential: FindOneUserResponse = await firstValueFrom(
      this.userSvc.findByLogin({ login: dto.username }),
    );

    if (potential.user == null || potential.user.email != dto.email) {
      return {
        error: 'Пользователь не был найден',
        status: HttpStatus.NOT_FOUND,
      };
    }

    const passwordToken: PasswordToken = new PasswordToken();
    passwordToken.token = uuidv4();
    passwordToken.createdAt = new Date();
    passwordToken.expiresAt = new Date(
      passwordToken.createdAt.getTime() + RESTORE_TOKEN_LIVE_TIME,
    );
    passwordToken.userId = potential.user.id;
    await this.passwordTokenRepo.saveToken(passwordToken);

    const response: PasswordRestoreResponse = await firstValueFrom(
      this.emailSvc.passwordRestore({
        token: passwordToken.token,
        email: dto.email,
      }),
    );

    return { error: response.error, status: response.status };
  }

  public async redirectRestore(
    dto: RedirectRequest,
  ): Promise<RedirectResponse> {
    const passwordToken: PasswordToken =
      await this.passwordTokenRepo.findByTokenValue(dto.token);

    if (
      passwordToken == null ||
      passwordToken.expiresAt.getTime() < new Date().getTime() ||
      passwordToken.confirmedAt != null
    ) {
      return {
        error: 'Токен не был найден или уже был использован',
        status: HttpStatus.NOT_FOUND,
        message: 'not-found',
      };
    }

    const user: FindOneUserResponse = await firstValueFrom(
      this.userSvc.findById({ id: passwordToken.userId }),
    );

    if (user.user == null) {
      return {
        error: 'Пользователь не был найден',
        status: HttpStatus.BAD_REQUEST,
        message: 'user-not-found',
      };
    }
    return { error: null, status: HttpStatus.OK, message: null };
  }

  public async updatePassword(
    dto: UpdatePasswordRequest,
  ): Promise<UpdatePasswordResponse> {
    const passwordToken: PasswordToken =
      await this.passwordTokenRepo.findByTokenValue(dto.token);

    passwordToken.confirmedAt = new Date();
    await this.passwordTokenRepo.saveToken(passwordToken);

    return await firstValueFrom(
      this.userSvc.changePassword({
        password: await bcrypt.hash(dto.password, 5),
        uuid: passwordToken.userId,
      }),
    );
  }

  public async confirm(dto: ConfirmRequest): Promise<ConfirmResponse> {
    const confirmationToken: ConfirmationToken =
      await this.confirmationTokenRepo.findByTokenValue(dto.token);
    if (
      confirmationToken == null ||
      confirmationToken.confirmedAt != null ||
      confirmationToken.expiresAt.getTime() < new Date().getTime()
    ) {
      return {
        message: 'not-found',
        error: 'Токен не существует',
        status: HttpStatus.NOT_FOUND,
      };
    }

    const response: ConfirmAccountResponse = await firstValueFrom(
      this.userSvc.confirmAccount({ uuid: confirmationToken.userId }),
    );

    if (response.status != HttpStatus.OK) {
      return {
        error: response.error,
        message: 'not-fine',
        status: response.status,
      };
    }
    confirmationToken.confirmedAt = new Date();
    await this.confirmationTokenRepo.saveToken(confirmationToken);
    return { message: 'fine', error: null, status: HttpStatus.OK };
  }

  private async validatePassword(dto: LoginRequestDto) {
    const response: GetHashedPasswordResponse = await firstValueFrom(
      this.userSvc.getHashedPassword({ login: dto.login }),
    );
    return await bcrypt.compare(dto.password, response.password);
  }
}
