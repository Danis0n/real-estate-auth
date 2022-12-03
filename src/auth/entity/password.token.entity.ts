import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';

@Entity('password_token')
export class PasswordToken extends BaseEntity {
  @PrimaryColumn({ name: 'token_id' })
  public id!: number;

  @Column({ name: 'token_value', nullable: false, type: 'varchar' })
  public token!: string;

  @Column({ name: 'user_id', nullable: false, type: 'uuid' })
  public user_id!: string;

  @Column({ name: 'created_at', nullable: false, type: 'timestamp' })
  public createdAt!: Date;

  @Column({ name: 'expires_at', nullable: false, type: 'timestamp' })
  public expiresAt!: Date;

  @Column({ name: 'confirmed_at', nullable: true, type: 'timestamp' })
  public confirmedAt!: Date;
}
