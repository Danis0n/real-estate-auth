import { ConfirmationToken } from '../entity/confirmation.token.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

export class ConfirmationTokenRepository {
  @InjectRepository(ConfirmationToken)
  private readonly confirmationTokenRepository: Repository<ConfirmationToken>;

  public async saveToken(token: ConfirmationToken): Promise<ConfirmationToken> {
    return this.confirmationTokenRepository.save(token);
  }

  public async findByTokenValue(token: string): Promise<ConfirmationToken> {
    return this.confirmationTokenRepository.findOne({ where: { token: token } });
  }
}
