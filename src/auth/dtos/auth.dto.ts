import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  ArrayNotEmpty,
  IsArray,
  IsEmail,
  IsEnum,
  IsOptional,
  IsPhoneNumber,
  IsString,
  IsStrongPassword,
  isArray,
  isPhoneNumber,
} from 'class-validator';
export enum SportInterestArray {
  Football = 'Football',
  Shooting = 'Shooting',
  Skiing = 'Skiing',
  Bandy = 'Bandy',
  Rugby = 'Rugby',
  Motorsports = 'Motorsports',
  Ice_Hockey = 'Ice_Hockey',
  Basketball = 'Basketball',
}

export class SignupDTO {
  @ApiProperty({ example: 'vamp@gmail.com' })
  @IsEmail()
  @IsOptional()
  @Transform(({ value }) => value.toLowerCase()) // Convert to lowercase
  readonly email: string;

  @ApiProperty({ example: 'Vamp@123' })
  @IsStrongPassword()
  readonly password: string;

  @ApiProperty({ example: '09876543211' })
  @IsPhoneNumber()
  readonly phone_number: number;

  @ApiProperty({ isArray: true, enum: SportInterestArray, example: [SportInterestArray.Football] })
  @IsArray()
  @ArrayNotEmpty()
  @IsEnum(SportInterestArray, { each: true })
  readonly sport_interested: SportInterestArray[];
}

export class LoginDTO {
  @ApiPropertyOptional({
    description: 'user unique email',
    example: 'vamp@gmail.com',
  })
  @IsEmail()
  @IsOptional()
  @Transform(({ value }) => value.toLowerCase()) // Convert to lowercase
  readonly email: string;

  @ApiPropertyOptional({ example: '09876543211' })
  @IsPhoneNumber()
  readonly phone_number: number;

  @ApiProperty({ example: 'Vamp@123' })
  @IsString()
  readonly password: string;
}

export class otpDTO {
  @ApiProperty({ example: 'vamp@gmail.com' })
  @IsEmail()
  @IsOptional()
  @Transform(({ value }) => value.toLowerCase())
  readonly email: string;

  @ApiProperty({ example: '8790' })
  @IsString()
  readonly otp: string;
}

export class resendOTP {
  @ApiProperty({ example: 'vamp@gmail.com' })
  @IsEmail()
  @IsOptional()
  @Transform(({ value }) => value.toLowerCase())
  readonly email: string;

  @ApiProperty({ example: '2345' })
  @IsString()
  @IsOptional()
  readonly otp: string;
}

export class EmailDTO {
  @ApiPropertyOptional({ example: 'vamp@gmail.com' })
  @IsEmail()
  @IsOptional()
  @Transform(({ value }) => value.toLowerCase())
  readonly email: string;
}
