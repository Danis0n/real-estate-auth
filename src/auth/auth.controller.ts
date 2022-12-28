import { Controller, Inject } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import {
  AUTH_SERVICE_NAME,
  AuthResponse,
  ConfirmResponse,
  LoginResponse,
  LogoutResponse,
  RedirectResponse,
  RegisterResponse,
  RestorePasswordResponse,
  UpdatePasswordResponse,
  ValidateResponse,
} from './proto/auth.pb';
import { AuthService } from './service/auth.service';

@Controller('refresh')
export class AuthController {
  @Inject(AuthService)
  private readonly service: AuthService;

  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  private async register(payload): Promise<RegisterResponse> {
    return this.service.register(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  private async login(payload): Promise<LoginResponse> {
    return this.service.login(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Auth')
  private async refresh(payload): Promise<AuthResponse> {
    return this.service.refresh(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Validate')
  private async validate(payload): Promise<ValidateResponse> {
    return this.service.validate(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Logout')
  private async logout(payload): Promise<LogoutResponse> {
    return this.service.logout(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'RestorePassword')
  private async restorePassword(payload): Promise<RestorePasswordResponse> {
    return this.service.restorePassword(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'RedirectRestore')
  private async redirectRestore(payload): Promise<RedirectResponse> {
    return this.service.redirectRestore(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'UpdatePassword')
  private async updatePassword(payload): Promise<UpdatePasswordResponse> {
    return this.service.updatePassword(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Confirm')
  private async confirm(payload): Promise<ConfirmResponse> {
    return this.service.confirm(payload);
  }
}
