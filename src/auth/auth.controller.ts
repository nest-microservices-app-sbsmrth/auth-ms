import { Controller } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';

@Controller()
export class AuthController {
  constructor() {}

  @MessagePattern('auth.register.user')
  registerUser() {
    return 'User registered successfully';
  }

  @MessagePattern('auth.login.user')
  loginUser() {
    return 'User logged in successfully';
  }

  @MessagePattern('auth.verify.user')
  verifyUser() {
    return 'User verified successfully';
  }
}
