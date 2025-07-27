import { IsNotEmpty, IsString } from 'class-validator';

export class TwoFactorLoginDTO {
  @IsNotEmpty()
  @IsString()
    tempToken: string;

  @IsNotEmpty()
  @IsString()
    code: string;
}
