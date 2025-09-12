import * as crypto from 'crypto';
import { Readable, Writable } from 'stream';
import { keysConfig } from '@/config/keys.config';

const ALGORITHM = 'aes-256-cbc';
const { encryptPrivate: KEY } = keysConfig();

export function encrypt(text: string): Promise<string> {
  const iv = crypto.randomBytes(16);

  return new Promise((resolve, reject) => {
    const readable = Readable.from([text]);
    const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
    const chunks: Buffer[] = [];

    const writable = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(chunk);
        callback();
      },
    });

    readable
      .pipe(cipher)
      .pipe(writable)
      .on('finish', () => resolve(`${iv.toString('hex')}:${Buffer.concat(chunks).toString('hex')}`))
      .on('error', reject);
  });
}

export function decrypt(encryptedText: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const [ivHex, encrypted] = encryptedText.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
    const chunks: Buffer[] = [];

    const readable = Readable.from([Buffer.from(encrypted, 'hex')]);

    const writable = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(chunk);
        callback();
      },
    });

    readable
      .pipe(decipher)
      .pipe(writable)
      .on('finish', () => resolve(Buffer.concat(chunks).toString('utf8')))
      .on('error', reject);
  });
}
