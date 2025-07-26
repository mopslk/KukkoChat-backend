import {
  registerDecorator,
  ValidationArguments,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '@/prisma/prisma.service';
import { ERROR_MESSAGES } from '@/constants/error-messages';

type PrismaModelNames = Prisma.ModelName;

@ValidatorConstraint({ name: 'uniqueConstraint', async: true })
@Injectable()
export class UniqueConstraint implements ValidatorConstraintInterface {
  constructor(
    private prisma: PrismaService,
  ) {}

  async validate(value: any, args: ValidationArguments) {
    const [entity] = args.constraints as [PrismaModelNames];
    const model = this.prisma[entity.toLowerCase()];

    const row = await model.findUnique({
      where: {
        [args.property]: value,
      },
    });
    return row === null;
  }
}

export function Unique(entity: PrismaModelNames, validationOptions?: ValidationOptions) {
  return (object: any, propertyName: string) => {
    registerDecorator({
      target  : object.constructor,
      propertyName,
      options : validationOptions ?? {
        message: ERROR_MESSAGES.UNIQUE_ERROR,
      },
      constraints : [entity],
      validator   : UniqueConstraint,
    });
  };
}
