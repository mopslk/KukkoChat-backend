import {
  Controller, Get, Inject, Param, Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { join } from 'path';
import { Public } from '@/utils/decorators/public.decorator';
import { ConfigType } from '@nestjs/config';
import { filesConfig } from '@/config/files.config';
import { FilesService } from './files.service';

@Controller()
export class FilesController {
  constructor(
    private readonly filesService: FilesService,
    @Inject(filesConfig.KEY)
    private storageConfig: ConfigType<typeof filesConfig>,
  ) {}

  @Get(':folder/:file')
  @Public()
  async getFile(@Param('folder') folder: string, @Param('file') file: string, @Res() res: Response) {
    const path = join(folder, file);

    const isFileExist = await this.filesService.checkFileExists(path);

    if (!isFileExist) {
      res.sendStatus(404);
      return;
    }

    res.sendFile(path, { root: this.storageConfig.basePath });
  }
}
