import { JwtService as Jwt } from '@nestjs/jwt';
import { Inject } from '@nestjs/common';
import { UserDto } from '../dto/user.dto';
import { RefreshToken } from '../entity/refresh.token.entity';
import { RoleMapper } from '../mapper/role.mapper';
import { RefreshTokenMapper } from '../mapper/refresh.token.mapper';
import { RefreshTokenRepository } from '../repository/refresh.token.repository';
import { AtJwtPayload, RtJwtPayload } from '../dto/jwt.dto';
import {
  JWT_ACCESS_TOKEN_LIVE_TIME,
  JWT_REFRESH_TOKEN_LIVE_TIME,
} from '../config/auth-constants';

export class JwtService {
  @Inject(Jwt)
  private readonly jwt: Jwt;

  @Inject(RoleMapper)
  private readonly roleMapper: RoleMapper;

  @Inject(RefreshTokenMapper)
  private readonly refreshTokenMapper: RefreshTokenMapper;

  @Inject(RefreshTokenRepository)
  private readonly refreshTokenRepo: RefreshTokenRepository;

  public async generateTokens(user: UserDto) {
    const roles = this.roleMapper.mapToStrings(user.roles);
    const refreshToken: string = this.createRefreshToken(user);
    const accessToken: string = this.createAccessToken(user, roles);
    const token: RefreshToken = this.refreshTokenMapper.mapToNewRefreshToken(
      refreshToken,
      user.id,
    );
    await this.refreshTokenRepo.saveToken(token);
    return { refreshToken: refreshToken, accessToken: accessToken };
  }

  public createRefreshToken(user: UserDto): string {
    return this.jwt.sign(
      { id: user.id, login: user.userLogin.login },
      { expiresIn: JWT_REFRESH_TOKEN_LIVE_TIME },
    );
  }

  public createAccessToken(user: UserDto, roles: string[]): string {
    return this.jwt.sign(
      {
        id: user.id,
        login: user.userLogin.login,
        roles: roles,
      },
      { expiresIn: JWT_ACCESS_TOKEN_LIVE_TIME },
    );
  }

  public decodeAToken(token: string): AtJwtPayload {
    return <AtJwtPayload>this.jwt.decode(token);
  }

  public decodeRToken(token: string): RtJwtPayload {
    return <RtJwtPayload>this.jwt.decode(token);
  }

  public verifyToken(token: string) {
    try {
      return this.jwt.verify(token, { ignoreExpiration: false });
    } catch (err) {
      console.log(err);
    }
  }
}
