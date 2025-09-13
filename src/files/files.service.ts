import { Inject, Injectable } from '@nestjs/common';
import * as fs from 'node:fs/promises';
import { join } from 'path';
import { ConfigType } from '@nestjs/config';
import { filesConfig } from '@/config/files.config';

@Injectable()
export class FilesService {
  constructor(
    @Inject(filesConfig.KEY)
    private storageConfig: ConfigType<typeof filesConfig>,
  ) {}

  async deleteFile(path: string): Promise<void> {
    await fs.rm(path);
  }

  async checkFileExists(path: string): Promise<boolean> {
    try {
      await fs.access(join(this.storageConfig.basePath, path));
      return true;
    } catch {
      return false;
    }
  }
}
