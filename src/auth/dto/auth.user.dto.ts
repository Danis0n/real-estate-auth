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
}

export class LoginRequestDto implements LoginRequest {
  readonly login: string;
  readonly password: string;
}

export class LoginResponseDto implements LoginResponse {
  accessToken: string;
  error: string[];
  refreshToken: string;
  user: UserDto | undefined;
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
  accessToken: string;
}

export class ValidateRequestDto implements ValidateRequest {
  token: string;
}
