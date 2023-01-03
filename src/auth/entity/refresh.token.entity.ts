import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';

@Entity('refresh_token')
export class RefreshToken extends BaseEntity {
  @PrimaryColumn({ name: 'token_id' })
  public id!: number;

  @Column({ name: 'token_value', nullable: false, type: 'varchar' })
  public token!: string;

  @Column({ name: 'user_id', nullable: false, type: 'uuid' })
  public userId!: string;

  @Column({ name: 'date_of_created', nullable: false, type: 'timestamp' })
  public creationDate!: Date;
}
