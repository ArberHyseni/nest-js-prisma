import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon2 from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { excludeFromObject } from 'src/helpers/excludePassword';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { sign } from 'crypto';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {}
  async signup({ email, password }: AuthDto) {
    try {
      const hashedPassword = await argon2.hash(password);

      const user = await this.prisma.user.create({
        data: {
          email,
          hash: hashedPassword,
        },
        select: {
          id: true,
          email: true,
          createdAt: true,
        },
      });

      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        throw new ForbiddenException('Email must be unique')
      }
    }
  }

  async login({email, password}: AuthDto) {
    const user = await this.prisma.user.findUnique({
        where: {
            email
        }
    })

    if (!user) {
        throw new NotFoundException('Wrong credentials')
    }

    const isPwCorrect = await argon2.verify(user.hash, password)

    if (!isPwCorrect) {
        throw new ForbiddenException('Wrong credentials')
    }

    const token = await this.signToken(user.id, user.email)

    return token;
  }

  async signToken(userId: number, email: string): Promise<{access_token: string}> {
    const payload = {
        userId,
        email
    }

    const signedToken = await this.jwt.signAsync(payload, {
        expiresIn: '15m',
        secret: this.config.get('JWT_SECRET')
    })

    return {
        access_token: signedToken
    }
  }
}
