import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RefreshToken } from '../entity/refresh.token.entity';

export class RefreshTokenRepository {
  @InjectRepository(RefreshToken)
  private readonly refreshTokenRepository: Repository<RefreshToken>;

  public async saveToken(token: RefreshToken): Promise<RefreshToken> {
    return this.refreshTokenRepository.save(token);
  }

  public async findByTokenValue(token: string): Promise<RefreshToken> {
    return this.refreshTokenRepository.findOne({ where: { token: token } });
  }

  public async deleteTokensByUser(uuid: string) {
    return this.refreshTokenRepository.delete({ user_id: uuid });
  }
}
