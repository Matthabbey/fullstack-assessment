import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { UsersService } from '../users/users.service';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  constructor(private readonly userService: UsersService) {}
  private logger = new Logger('HTTP');

  async use(request: Request, response: Response, next: NextFunction) {
    const { ip, method, originalUrl, headers } = request;
    // console.log(request.headers['x-forwarded-for'])
    // console.log(request.headers)
    const userAgent = request.get('user-agent') || '';

    const { statusCode } = response;
    response.on('finish', () => {
      const contentLength = response.get('content-length') || '';
      this.logger.log(
        `${method} ${originalUrl} ${statusCode} - ${headers.referer} ${contentLength} - ${userAgent} ${ip} - ${request.socket.remoteAddress}`,
      );
    });

    const send = response.send;
    response.send = (exitData) => {
      if (
        response
          ?.getHeader('content-type')
          ?.toString()
          .includes('application/json')
      ) {
        const statusCode = exitData?.code || response.statusCode;

        console.log({
          code: statusCode,
          // exit: jsonData.data.access_token,
          endDate: new Date(),
        });
      }
      response.send = send;
      return response.send(exitData);
    };

    next();
  }
}
