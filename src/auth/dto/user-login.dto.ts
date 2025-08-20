import { IsNotEmpty, IsString } from 'class-validator';
import { DeviceData } from '@/utils/types';

export class UserLoginDto {
  @IsNotEmpty()
  @IsString()
    login: string;

  @IsNotEmpty()
  @IsString()
    password: string;

  @IsNotEmpty()
  @IsString()
    deviceId: string;

  @IsNotEmpty()
  @IsString()
    deviceName: string;

  getDeviceData(): DeviceData {
    return {
      deviceId   : this.deviceId,
      deviceName : this.deviceName,
    };
  }
}
