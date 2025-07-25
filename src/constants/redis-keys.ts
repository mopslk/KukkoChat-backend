export const REDIS_KEYS = {
  twoFaSecret: (userId: string | number) => `auth:2fa:secret:${userId}`,
};
