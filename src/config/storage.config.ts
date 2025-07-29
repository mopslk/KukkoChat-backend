import { diskStorage } from 'multer';
import type { MulterOptions } from '@nestjs/platform-express/multer/interfaces/multer-options.interface';
import { editFileName, fileFilter, getDestinationFolder } from '@/utils/helpers/file';
import { MulterModuleOptions } from '@nestjs/platform-express';

export const multerConfig: MulterOptions = {
  storage: diskStorage({
    destination: async (_req, _file, callback) => {
      const folder = await getDestinationFolder();
      callback(null, folder);
    },
    filename: editFileName,
  }),
  fileFilter,
};

export const multerModuleConfig: MulterModuleOptions = {
  dest: process.env.BASE_FILES_PATH,
};
