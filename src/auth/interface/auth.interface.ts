import { SportInterestArray } from '../dtos';

export interface AuthPayload {
  id: string;
  email: string;
  verified: boolean;
}

export interface ILoginInstance {
  email: string;
  password: string;
}

export interface IOtpInstance {
  email: string;
  otp: string;
}

export interface IResendOtpInstance {
  email: string;
  otp: string;
}

export interface IEmail {
  email: string;
}

export interface ISignupInstance {
  email?: string;
  password: string;
  sport_interested: SportInterestArray[];
}

export interface IUserInstance {
  id: string;
  email: string;
  phone_number: string;
  is_email_verified: boolean;
  is_phone_number_verified: boolean;
}
