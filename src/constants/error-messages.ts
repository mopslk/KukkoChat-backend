export const ERROR_MESSAGES = {
  INVALID_REFRESH_TOKEN     : 'Invalid refresh token',
  INVALID_2FA_CODE          : 'Invalid two-factor authentication code',
  TOO_MANY_ATTEMPTS         : 'Too many attempts, try again later',
  NOT_FOUND_2FA             : 'Not found 2fa, regenerate qr-code',
  FAILED_CHAT_CREATE        : 'Failed to create chat',
  PRIVATE_CHAT_UPDATE       : 'Private chat can\'t be updated',
  TOKEN_INVALIDATED         : 'Token has been invalidated',
  MATCH_ERROR               : 'The $property field must be the same as the $constraint1',
  UNIQUE_ERROR              : 'This $property already used',
  FILE_EXTENSION_ERROR      : (extension: string) => `${extension} file extension are not allowed`,
  INVALID_LOGIN_CREDENTIALS : 'Invalid login or password',
  INVALID_2FA_TEMP_TOKEN    : 'Invalid or expired 2FA token',
};
