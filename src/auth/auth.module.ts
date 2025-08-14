import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { envs } from 'src/config';
import { PrismaService } from './providers/prisma.service';

@Module({
  controllers: [AuthController],
  providers: [AuthService, PrismaService],
  imports: [
    JwtModule.registerAsync({
      imports: [],
      inject: [],
      useFactory: () => ({
        global: true,
        secret: envs.jwt.secret,
        signOptions: { expiresIn: envs.jwt.expiration },
      }),
    }),
  ],
  exports: [JwtModule],
})
export class AuthModule {}
