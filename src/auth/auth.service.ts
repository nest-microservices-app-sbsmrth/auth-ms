import { HttpStatus, Injectable, Logger } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from './providers/prisma.service';
import { JwtPayload } from './interfaces';
import { envs } from 'src/config';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('AuthService');
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, password, firstname, lastname } = registerUserDto;

    try {
      const user = await this.prisma.user.findUnique({
        where: { email },
      });

      if (user) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Email or password is incorrect',
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = await this.prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          firstname,
          lastname,
        },
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: __, ...newUserData } = newUser;

      return newUserData;
    } catch (error) {
      this.handleError(error);
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Email or password is incorrect',
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Email or password is incorrect',
        });
      }

      const token = this.signJWT({ user: { id: user.id } });

      return {
        user: {
          firstname: user.firstname,
          lastname: user.lastname,
          email: user.email,
          roles: user.roles,
        },
        access_token: token,
      };
    } catch (error) {
      this.logger.error('Error logging in user', error);
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: 'Failed to login user',
      });
    }
  }

  verifyToken(token: string) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { sub, iat, exp, ...tokenData } = this.jwtService.verify<
        JwtPayload & { sub: string; iat: number; exp: number }
      >(token, {
        secret: envs.jwt.secret,
      });

      return {
        newToken: this.signJWT(tokenData),
        ...tokenData,
      };
    } catch (error) {
      this.logger.error('Error verifying token', error);
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid token',
      });
    }
  }

  private handleError(error: any) {
    this.logger.error('Error occurred', error);

    if (error instanceof RpcException) {
      throw error;
    }

    throw new RpcException({
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'Unknown error occurred',
    });
  }

  private signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
}
