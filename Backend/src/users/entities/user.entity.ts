import { SportInterestEnum } from 'src/auth/dtos';
import {
  BeforeInsert,
  Column,
  CreateDateColumn,
  DeleteDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

export enum Gender {
  Male = 'male',
  Female = 'female',
  Other = 'other',
}
export enum Role {
  USER = 'user',
  ADMIN = 'admin',
}
@Entity('users')
export class User {
  @BeforeInsert()
  toLowerCase() {
    this.email = this.email?.toLowerCase();
  }

  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('text')
  gender: Gender;

  @Column({ length: 255, unique: true, nullable: true })
  email: string;

  @Column({ length: 255, nullable: false })
  sport_interested: SportInterestEnum;

  @Column({ length: 255, nullable: false })
  password: string;

  @Column({ length: 255 })
  otp: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  otp_expiry: Date;

  @Column({ length: 255, nullable: true })
  refresh_token: string;

  @Column({ length: 255, nullable: true, unique: true })
  phone_number: string;

  @Column({ type: 'boolean', nullable: false, default: false })
  is_email_verified: boolean;

  @Column({ nullable: true })
  new_password_token: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  password_reset_expire: Date;

  @CreateDateColumn({ type: 'timestamp' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp', nullable: true })
  updated_at?: Date;

  @DeleteDateColumn({ name: 'deleted_at', type: 'timestamp', nullable: true })
  deleted_at: Date | null;
}
