import { Body, Controller, Get, Post, Req } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDto } from "./dto/auth.dto";

@Controller('auth')
export class AuthController{

    constructor(private authService: AuthService) {}

    @Post('signup')
    async signup(@Body() dto: AuthDto) {
        console.log(dto)
        const user = await this.authService.signup(dto)

        return user;
    }

    @Post('login')
    async login(@Body() dto: AuthDto) {
        const user = await this.authService.login(dto)
        console.log('hello')

        return user;
    }
}