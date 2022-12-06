import { RefreshToken } from '../entity/refresh.token.entity';

export class RefreshTokenMapper {
  public mapToNewRefreshToken(token: string, id: string): RefreshToken {
    const refreshToken: RefreshToken = new RefreshToken();
    refreshToken.creationDate = new Date();
    refreshToken.user_id = id;
    refreshToken.token = token;
    return refreshToken;
  }
}
