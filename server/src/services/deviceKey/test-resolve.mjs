// node --test loader for the device-key unit tests.
//
// Node 24 strips TypeScript types natively, but ES module resolution needs
// file extensions, while the production code keeps extensionless relative
// imports (`from './der'`, compiled by tsc to CommonJS). This synchronous
// resolve hook retries an extensionless relative specifier with ".ts".
// No dependency. Used only by the tests:
//
//   cd server
//   node --import ./src/services/deviceKey/test-resolve.mjs --disable-warning=MODULE_TYPELESS_PACKAGE_JSON \
//        --test "src/services/deviceKey/*.test.ts"
//
// (also: npm run test:device-keys)
import { registerHooks } from 'node:module';

registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context);
    } catch (err) {
      const relative = specifier.startsWith('./') || specifier.startsWith('../');
      if (relative && !/\.[cm]?[jt]s$/.test(specifier) && err && err.code === 'ERR_MODULE_NOT_FOUND') {
        return nextResolve(`${specifier}.ts`, context);
      }
      throw err;
    }
  },
});
