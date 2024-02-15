import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  UseFilters,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiConflictResponse,
  ApiConsumes,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
// import { HttpExceptionFilter, RefreshTokenGuard } from '../middlewares';
import { AuthService } from './auth.service';
import { EmailDTO, LoginDTO, SignupDTO, otpDTO, resendOTP } from './dtos';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AllExceptionsFilter } from '../middlewares/allException.filter';
import { RefreshTokenGuard } from '../middlewares';

@ApiTags('Auth')
@Controller('auth')
@UseFilters(AllExceptionsFilter) //Here
@UsePipes(new ValidationPipe())
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiCreatedResponse({ description: 'Successful' })
  @ApiUnauthorizedResponse({
    description: 'Unauthorized',
  })
  @ApiBadRequestResponse({
    description: 'Bad request',
  })
  @UseGuards(RefreshTokenGuard)
  @ApiBearerAuth()
  @Get('refresh')
  refreshTokens(@Req() req: Request) {
    return this.authService.refreshTokens(req);
  }

  @ApiOkResponse({ description: 'successful' })
  @ApiUnauthorizedResponse({ description: 'unauthorized user' })
  @ApiBadRequestResponse({ description: 'bad request' })
  @ApiCreatedResponse({ description: 'account successfully created' })
  @ApiConsumes('multipart/form-data')
  @Post('signup')
  async onUserSignUp(@Body() signupDTO: SignupDTO) {
    return await this.authService.signUp(signupDTO);
  }

  @ApiCreatedResponse({ description: 'email verification successful' })
  @Post('account/verification')
  async verifyEmail(@Body() otp: otpDTO) {
    return await this.authService.accountOtpVerification(otp);
  }

  @ApiForbiddenResponse({ description: 'forbidden response' })
  @ApiOkResponse({ description: 'successful' })
  @ApiBadRequestResponse({
    description: 'Bad request',
  })
  @ApiCreatedResponse({ description: 'resend verification otp' })
  @Post('resend/verification/otp')
  async resendUserOTP(@Body() info: resendOTP) {
    return await this.authService.resendAccountOtpVerification(info);
  }

  @ApiConflictResponse({ description: 'conflict responses' })
  @ApiOkResponse({ description: 'successful' })
  @ApiBadRequestResponse({ description: 'bad request' })
  @Post('login')
  async onUserLogin(@Body() loginDTO: LoginDTO) {
    return await this.authService.login(loginDTO);
  }

  @ApiForbiddenResponse({ description: 'forbidden response' })
  @ApiUnauthorizedResponse({
    description: 'Unauthorized',
  })
  @ApiBadRequestResponse({
    description: 'Bad request',
  })
  @ApiCreatedResponse({ description: '' })
  @Post('email/forgot-password')
  async sendEmailForgotPassword(@Req() req: Request, @Body() body: EmailDTO) {
    return await this.authService.sendEmailForgotPassword(req);
  }

  @ApiForbiddenResponse({ description: 'forbidden response' })
  @ApiUnauthorizedResponse({
    description: 'Unauthorized',
  })
  @ApiCreatedResponse({ description: 'reset password otp successful' })
  @ApiNotFoundResponse({ description: 'not found' })
  @Post('email/forgot-password/verify-otp')
  async verifyPasswordResetOTP(@Body() verify: otpDTO) {
    return await this.authService.verifyPasswordOTP(verify);
  }

  @ApiForbiddenResponse({ description: 'forbidden response' })
  @ApiUnauthorizedResponse({
    description: 'Unauthorized',
  })
  @ApiBadRequestResponse({
    description: 'Bad request',
  })
  @ApiCreatedResponse({ description: 'password reset successful' })
  @Post('email/reset-password')
  async setNewPassord(@Body() resetPassword: LoginDTO) {
    return await this.authService.resetPassword(resetPassword);
  }
}
