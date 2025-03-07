import { defaultLogger } from '@onekeyhq/shared/src/logger/logger';
import platformEnv from '@onekeyhq/shared/src/platformEnv';

import errorToastUtils from '../errors/utils/errorToastUtils';
import errorUtils from '../errors/utils/errorUtils';
import { formatDateFns } from '../utils/dateUtils';

import {
  throwCrossError,
  warningIfNotRunInBackground,
} from './backgroundUtils';

const INTERNAL_METHOD_PREFIX = 'INTERNAL_';
const PROVIDER_API_METHOD_PREFIX = 'PROVIDER_API_';

// Is a any record, but namely use `PropertyDescriptor['value']`
export type IBackgroundUnknownTarget = Record<
  string,
  PropertyDescriptor['value']
>;
export type IBackgroundUnknownFunc = (...args: unknown[]) => unknown;

const isFunction = (fn?: any): fn is IBackgroundUnknownFunc =>
  !!fn && {}.toString.call(fn) === '[object Function]';

function backgroundClass() {
  // @ts-ignore
  return function (constructor) {
    if (process.env.NODE_ENV !== 'production') {
      return class extends constructor {
        constructor(...args: any) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-call
          super(...args);
          warningIfNotRunInBackground({
            // eslint-disable-next-line @typescript-eslint/restrict-template-expressions, @typescript-eslint/no-unsafe-member-access
            name: `[${constructor?.name || ''}] Class`,
            target: this,
          });
        }
      };
    }

    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return constructor;
  };
}

export function isCorrectDevOnlyPassword(
  password: string | undefined,
): boolean {
  // 20240625-onekey-debug
  const correctPwd = `${formatDateFns(new Date(), 'yyyyMMdd')}-onekey-debug`;
  return password === correctPwd;
}

export type IBackgroundMethodWithDevOnlyPassword = {
  $$devOnlyPassword: string;
};

export function checkDevOnlyPassword(
  params: IBackgroundMethodWithDevOnlyPassword,
  methodName?: string,
) {
  if (!isCorrectDevOnlyPassword(params?.$$devOnlyPassword)) {
    throwCrossError(
      `You are not allowed to call this method, devOnlyPassword is wrong. method=${
        methodName || ''
      }`,
    );
  }
}

function createBackgroundMethodDecorator({
  prefix,
  devOnly = false,
}: {
  prefix: string;
  devOnly?: boolean;
}) {
  return function (
    target: IBackgroundUnknownTarget,
    methodName: string,
    descriptor: PropertyDescriptor,
  ) {
    if (typeof descriptor.value !== 'function') {
      throwCrossError(
        '@backgroundMethod() / providerApiMethod only available for method or function.',
        methodName,
      );
    }

    if (devOnly && platformEnv.isProduction && !platformEnv.isE2E) {
      // throwCrossError(
      //   '@backgroundMethodForDev() / providerApiMethod only available in development.',
      //   methodName,
      // );
    }

    if (devOnly) {
      // @ts-ignore
      target[`${prefix}${methodName}`] = function (p1, ...others) {
        // eslint-disable-next-line @typescript-eslint/no-this-alias
        const self = this;
        checkDevOnlyPassword(p1, methodName);
        // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
        return descriptor.value.call(self, p1, ...others);
      };
    } else {
      target[`${prefix}${methodName}`] = descriptor.value;
    }

    // return PropertyDescriptor
    // descriptor.value.$isBackgroundMethod = true;
    return descriptor;
  };
}

function backgroundMethod() {
  return createBackgroundMethodDecorator({
    prefix: INTERNAL_METHOD_PREFIX,
  });
}

function backgroundMethodForDev() {
  return createBackgroundMethodDecorator({
    prefix: INTERNAL_METHOD_PREFIX,
    devOnly: true,
  });
}

function providerApiMethod() {
  return createBackgroundMethodDecorator({
    prefix: PROVIDER_API_METHOD_PREFIX,
  });
}

function permissionRequired() {
  return function (
    _: IBackgroundUnknownTarget,
    __: string,
    descriptor: PropertyDescriptor,
  ) {
    const fn = descriptor.value;

    // Checks if "descriptor.value"
    // is a function or not
    if (isFunction(fn)) {
      descriptor.value = function (...args: Array<any>): any {
        // if (this.chainId !== '0x1') {
        //   throw new Error(this.chainId + ' chain not matched');
        // }
        const result = fn.apply(this, args);
        return result;
      };
    }
    return descriptor;
  };
}

function bindThis() {
  // eslint-disable-next-line @typescript-eslint/ban-types
  return function <T extends Function>(
    // eslint-disable-next-line @typescript-eslint/ban-types
    target: object,
    propertyKey: string,
    descriptor: TypedPropertyDescriptor<T>,
  ): TypedPropertyDescriptor<T> | void {
    if (!descriptor || typeof descriptor.value !== 'function') {
      throw new TypeError(
        `Only methods can be decorated with @bind. <${propertyKey}> is not a method!`,
      );
    }

    // return PropertyDescriptor
    return {
      configurable: true,
      get(this: T): T {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const bound: T = descriptor.value!.bind(this);
        // Credits to https://github.com/andreypopp/autobind-decorator for memoizing the result of bind against a symbol on the instance.
        Object.defineProperty(this, propertyKey, {
          value: bound,
          configurable: true,
          writable: true,
        });
        return bound;
      },
    };
  };
}

// TODO implement call toast from background methods:
//    backgroundShowToast / backgroundToast / toastBackground / showToastFromBackground
export function toastIfError() {
  return (
    target: Record<any, any>,
    propertyKey: string,
    descriptor: TypedPropertyDescriptor<any>,
  ) => {
    const originalMethod = descriptor.value as (...args: any[]) => Promise<any>;

    descriptor.value = async function (...args: any[]) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call
        return await originalMethod.apply(this, args);
      } catch (error: unknown) {
        errorToastUtils.toastIfError(error);
        throw error;
      }
    };

    return descriptor;
  };
}

export {
  INTERNAL_METHOD_PREFIX,
  PROVIDER_API_METHOD_PREFIX,
  backgroundClass,
  backgroundMethod,
  backgroundMethodForDev,
  bindThis,
  permissionRequired,
  providerApiMethod,
};
