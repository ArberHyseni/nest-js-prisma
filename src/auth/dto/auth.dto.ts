import { Optional } from "@nestjs/common";
import { IsEmail, IsNotEmpty, IsOptional, IsString, MinLength, isNotEmpty } from "class-validator";

export class AuthDto {
    @IsEmail()
    @IsNotEmpty()
    email: string;
    @MinLength(8)
    @IsString()
    @IsNotEmpty()
    password?: string;
}