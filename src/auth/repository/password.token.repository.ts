import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PasswordToken } from '../entity/password.token.entity';

export class PasswordTokenRepository {
  @InjectRepository(PasswordToken)
  private readonly userRepository: Repository<PasswordToken>;

  public async saveToken(token: PasswordToken): Promise<PasswordToken> {
    return this.userRepository.save(token);
  }

  public async findByTokenValue(token: string): Promise<PasswordToken> {
    return this.userRepository.findOne({ where: { token: token } });
  }
}
