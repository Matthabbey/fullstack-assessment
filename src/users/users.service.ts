/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities';
import { SuccessfulResponse } from 'src/middlewares';
import { IUserInstance } from './interface';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async userProfile(req: any) {
    const userId = req.user.userId;
    try {
      const find_user = await this.userRepository.findOne({
        where: { id: userId },
      });
      if (!find_user) {
        throw new UnauthorizedException('Unauthorized access');
      }

      const {
        id,
        otp_expiry,
        password_reset_expire,
        // date_of_birth,
        password,
        new_password_token,
        otp,
        ...result
      } = find_user;

      return new SuccessfulResponse('User profile retrieved', HttpStatus.OK, result);
    } catch (e) {
      console.log(e);
    }
  }
  async editUserProfile(user: any, updateUserDTO: IUserInstance): Promise<any> {
    try {
      if (process.env.DEBUG_ON === 'YES') console.log('In UserServiceUpdateUserProfile');
      const userId = user?.userId;

      const user_data = await this.userRepository.findOne({
        where: { id: userId },
      });

      if (!user_data) {
        return new UnauthorizedException('Unauthorized access');
      }

      if (process.env.DEBUG_ON === 'YES')
        console.log('In UserServiceUpdateUserProfile - after !user_data');

      const { occupation, gender } = updateUserDTO;
      // Update the user's properties
      user_data.gender = gender;
      const updated_user = await this.userRepository.save(user_data);

      const { id, otp, password, otp_expiry, new_password_token, password_reset_expire, ...data } =
        updated_user;
      return new SuccessfulResponse('User profile successfully updated', HttpStatus.OK, data);
    } catch (error) {
      console.log(error);
    }
  }
}
