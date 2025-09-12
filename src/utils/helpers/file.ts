import { extname, join } from 'path';
import * as fs from 'node:fs/promises';
import { randomBytes } from 'crypto';
import { encodeBase64 } from '@/utils/helpers/base64';
import type { Options as MulterOptions, DiskStorageOptions } from 'multer';
import { HttpException, HttpStatus } from '@nestjs/common';
import { AttachmentType } from '@prisma/client';
import { ERROR_MESSAGES } from '@/constants/error-messages';
import { filesConfig } from '@/config/files.config';

export const fileFilter: MulterOptions['fileFilter'] = (_req, file, callback) => {
  if (!file.originalname.match(/\.(jpg|jpeg|png|gif|mp4|docs)$/)) {
    return callback(new HttpException(
      ERROR_MESSAGES.FILE_EXTENSION_ERROR(extname(file.originalname)),
      HttpStatus.BAD_REQUEST,
    ));
  }
  return callback(null, true);
};

export const editFileName: DiskStorageOptions['filename'] = (_req, file, callback) => {
  const fileExtName = extname(file.originalname);
  const randomName = randomBytes(24)
    .toString('hex');

  callback(null, `${randomName}${fileExtName}`);
};

async function getLastCreatedFolder(directoryPath: string): Promise<string | null> {
  const folders = await fs.readdir(directoryPath, { withFileTypes: true });

  const foldersData = await Promise.all(folders.filter((dirent) => dirent.isDirectory())
    .map(async (dirent) => ({
      name : dirent.name,
      time : (await fs.stat(join(directoryPath, dirent.name))).mtime,
    })));

  return foldersData.sort((a, b) => b.time.getTime() - a.time.getTime())[0]?.name ?? null;
}

export async function getDestinationFolder() {
  const { basePath } = filesConfig();
  const currentDate = new Date().toLocaleDateString();

  let lastFolderName = await getLastCreatedFolder(basePath);
  const checkDate = encodeBase64(currentDate) === lastFolderName;

  if (!lastFolderName || !checkDate) {
    const encodeFolder = encodeBase64(currentDate);
    const path = join(basePath, encodeFolder);

    await fs.mkdir(path, { recursive: true });

    lastFolderName = await getLastCreatedFolder(basePath);
  }

  return join(basePath, lastFolderName);
}

export function getFileUrl(path: string): string {
  const { basePath, baseUrl } = filesConfig();
  const normalizedBasePath = basePath.replace(/^\.\//, '');
  const pathWithoutBasePath = path.replace(new RegExp(`^${normalizedBasePath}/?`), '');

  return join(baseUrl, 'api', pathWithoutBasePath);
}

export function getFileType(fileName: string): AttachmentType {
  const fileExtension = extname(fileName);

  switch (fileExtension) {
    case 'mp4':
      return AttachmentType.video;
    case 'gif':
      return AttachmentType.gif;
    case 'docs':
      return AttachmentType.docs;

    default:
      return AttachmentType.image;
  }
}
