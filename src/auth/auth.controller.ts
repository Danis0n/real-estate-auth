import { Controller, Inject } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import {
  AUTH_SERVICE_NAME,
  AuthResponse,
  LoginResponse,
  LogoutResponse,
  RegisterResponse,
  ValidateResponse,
} from './proto/auth.pb';
import { AuthService } from './service/auth.service';

@Controller('refresh')
export class AuthController {
  @Inject(AuthService)
  private readonly authService: AuthService;

  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  private async register(payload): Promise<RegisterResponse> {
    return this.authService.register(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  private async login(payload): Promise<LoginResponse> {
    return this.authService.login(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Auth')
  private async refresh(payload): Promise<AuthResponse> {
    return this.authService.refresh(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Validate')
  private async validate(payload): Promise<ValidateResponse> {
    return this.authService.validate(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Logout')
  private async logout(payload): Promise<LogoutResponse> {
    return this.authService.logout(payload);
  }
}
