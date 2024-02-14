import { Gender } from "../entities";

export interface IUserInstance {
    first_name: string;
    last_name: string;
    gender: Gender;
    email: string;
    phone_number: string;
    occupation: string;
    field: string
  }