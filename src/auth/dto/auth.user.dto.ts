import { LoginRequest, RegisterRequest } from '../proto/auth.pb';

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
