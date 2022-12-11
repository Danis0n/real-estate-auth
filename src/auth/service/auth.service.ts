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
import { AuthRequest, AuthResponse, ValidateResponse } from '../proto/auth.pb';
import { RefreshToken } from '../entity/refresh.token.entity';

@Injectable()
export class AuthService implements OnModuleInit {
  private userSvc: UserServiceClient;

  @Inject(USER_SERVICE_NAME)
  private readonly client: ClientGrpc;

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

  public async login(dto: LoginRequestDto): Promise<LoginResponseDto> {
    const response: FindOneUserResponse = await firstValueFrom(
      this.userSvc.findByLogin({
        login: dto.login,
      }),
    );
    const user: UserDto = response.user;
    if (user && (await this.validatePassword(dto))) {
      await this.refreshTokenRepo.deleteTokensByUser(user.id);
      const tokens: { accessToken; refreshToken } =
        await this.jwtService.generateTokens(user);
      return {
        user: user,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        error: null,
      };
    }
    return {
      accessToken: null,
      refreshToken: null,
      user: null,
      error: ['Неверный пароль или логин'],
    };
  }

  public async refresh(dto: AuthRequest): Promise<AuthResponseDto> {
    const token: RefreshToken = await this.refreshTokenRepo.findByTokenValue(
      dto.refreshToken,
    );
    if (token == null)
      return this.response(null, null, null, 'Токен не существует');

    if (
      this.jwtService.verifyToken(dto.refreshToken) !== null &&
      dto.refreshToken === token.token
    ) {
      const userId: string = this.jwtService.decodeRToken(dto.refreshToken).id;
      const response: FindOneUserResponse = await firstValueFrom(
        this.userSvc.findById({ id: userId }),
      );
      await this.refreshTokenRepo.deleteTokensByUser(response.user.id);
      const tokens: { accessToken; refreshToken } =
        await this.jwtService.generateTokens(response.user);
      return this.response(
        tokens.accessToken,
        tokens.refreshToken,
        response.user,
        null,
      );
    }
    return this.response(null, null, null, null);
  }

  public async logout(dto: LogoutRequestDto): Promise<LogoutResponseDto> {
    const decoded: AtJwtPayload = this.jwtService.decodeAToken(dto.accessToken);
    await this.refreshTokenRepo.deleteTokensByUser(decoded.id);
    return { status: 200 };
  }

  public async validate(dto: ValidateRequestDto): Promise<ValidateResponse> {
    const result: AtJwtPayload = await this.jwtService.verifyToken(dto.token);
    if (result) {
      return {
        status: HttpStatus.OK,
        error: null,
      };
    }
    return {
      status: HttpStatus.UNAUTHORIZED,
      error: ['UNAUTHORIZED'],
    };
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

  private async validatePassword(dto: LoginRequestDto) {
    const response: GetHashedPasswordResponse = await firstValueFrom(
      this.userSvc.getHashedPassword({ login: dto.login }),
    );
    const passwordEquals = await bcrypt.compare(
      dto.password,
      response.password,
    );
    return passwordEquals;
  }

  private response(at: string, rt: string, user: UserDto, error: string) {
    return {
      accessToken: at,
      refreshToken: rt,
      user: user,
      error: error,
    };
  }
}
