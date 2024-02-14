import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsEnum,
  IsOptional,
  IsPhoneNumber,
  IsString,
  IsStrongPassword,
  isPhoneNumber,
} from 'class-validator';
export enum SportInterestEnum {
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

  @ApiProperty({ enum: SportInterestEnum, example: SportInterestEnum.Football })
  @IsEnum(SportInterestEnum)
  readonly sport_interested: SportInterestEnum;
}

export class LoginDTO {
  @ApiProperty({
    description: 'user unique email',
    example: 'vamp@gmail.com',
  })
  @IsEmail()
  @IsOptional()
  @Transform(({ value }) => value.toLowerCase()) // Convert to lowercase
  readonly email: string;

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
