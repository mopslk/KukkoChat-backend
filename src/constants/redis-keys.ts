export const REDIS_KEYS = {
  twoFaSecret    : (userId: string | number) => `auth:2fa:secret:${userId}`,
  twoFaTempToken : (tempToken: string) => `auth:2fa:temp:${tempToken}`,
};
