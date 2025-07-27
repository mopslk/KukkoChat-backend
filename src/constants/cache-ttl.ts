export const CACHE_TTL = {
  second : (count: number) => 1000 * count,
  minute : (count: number) => 60000 * count,
  hour   : (count: number) => (60000 * 60) * count,
};
