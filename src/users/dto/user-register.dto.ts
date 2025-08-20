import { IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { Match } from '@/utils/decorators/match.decorator';
import { Unique } from '@/utils/decorators/unique.decorator';

export class UserRegisterDto {
  @IsNotEmpty()
  @IsString()
  @Unique('User')
    login: string;

  @IsString()
  @IsNotEmpty()
    name: string;

  @IsNotEmpty()
  @IsString()
    password: string;

  @Match('password')
    passwordConfirmation: string;

  @IsString()
  @IsOptional()
    bio: string | null;

  @IsString()
  @IsOptional()
    avatar: string | null;

  @IsString()
    deviceId: string;

  @IsString()
    deviceName: string;

  setPassword(value: string): void {
    this.password = value;
  }

  removePasswordConfirmationField(): void {
    delete this.passwordConfirmation;
  }
}
