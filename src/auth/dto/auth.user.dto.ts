import {
  AuthResponse,
  LoginRequest,
  LoginResponse,
  LogoutRequest,
  LogoutResponse,
  RegisterRequest,
  ValidateRequest,
} from '../proto/auth.pb';
import { UserDto } from './user.dto';
import { IsString } from 'class-validator';

export class RegisterRequestDto implements RegisterRequest {
  public readonly dateOfBirth: string;
  public readonly email: string;
  public readonly firstName: string;
  public readonly inn: string;
  public readonly lastName: string;
  public readonly login: string;
  public password: string;
  public readonly phone: string;
  public readonly link: string;
  public readonly role: string;
}

export class LoginRequestDto implements LoginRequest {
  @IsString()
  readonly login: string;
  @IsString()
  readonly password: string;
}

export class LoginResponseDto implements LoginResponse {
  accessToken: string;
  error: string;
  refreshToken: string;
  user: UserDto | undefined;
  status: number;
}

export class AuthResponseDto implements AuthResponse {
  accessToken: string;
  error: string;
  refreshToken: string;
  user: UserDto | undefined;
}

export class LogoutResponseDto implements LogoutResponse {
  status: number;
}

export class LogoutRequestDto implements LogoutRequest {
  readonly accessToken: string;
}

export class ValidateRequestDto implements ValidateRequest {
  readonly token: string;
}
