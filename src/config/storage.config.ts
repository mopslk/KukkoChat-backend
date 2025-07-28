import { diskStorage } from 'multer';
import type { MulterOptions } from '@nestjs/platform-express/multer/interfaces/multer-options.interface';
import { editFileName, fileFilter, getDestinationFolder } from '@/utils/helpers/file';

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
