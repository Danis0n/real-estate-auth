import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';

@Entity('confirmation_token')
export class ConfirmationToken extends BaseEntity {
  @PrimaryColumn({ name: 'token_id' })
  public id!: number;

  @Column({ name: 'token_value', nullable: false, type: 'varchar' })
  public token!: string;

  @Column({ name: 'user_id', nullable: false, type: 'uuid' })
  public userId!: string;

  @Column({ name: 'created_at', nullable: false, type: 'timestamp' })
  public createdAt!: Date;

  @Column({ name: 'expires_at', nullable: false, type: 'timestamp' })
  public expiresAt!: Date;

  @Column({ name: 'confirmed_at', nullable: true, type: 'timestamp' })
  public confirmedAt!: Date;
}
