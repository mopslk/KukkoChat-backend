import { SetMetadata } from '@nestjs/common';

export const ForbidIfUserHas = (field: string) => SetMetadata('ForbidIfUserHas', field);
