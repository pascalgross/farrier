// Karma configuration for the HostSeal web application.
//
// It sets only the browser. The frameworks, plugins and reporters come from Angular's own builder,
// which supplies a complete configuration and merges this on top; listing them here would pin versions
// that the builder is entitled to change.
//
// The launcher exists because CI, and any container, runs as root, where Chrome refuses to start
// without --no-sandbox. Disabling the sandbox is acceptable here and only here: the browser is running
// our own bundle inside a disposable container with no untrusted input anywhere near it.
module.exports = function (config) {
  config.set({
    // Naming any plugin replaces the builder's list rather than adding to it, so jasmine has to be
    // named alongside the launcher — without it the specs load and `describe` is undefined.
    frameworks: ['jasmine'],
    plugins: [require('karma-jasmine'), require('karma-chrome-launcher')],
    browsers: ['ChromeHeadlessNoSandbox'],
    customLaunchers: {
      ChromeHeadlessNoSandbox: {
        base: 'ChromeHeadless',
        flags: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
      },
    },
    restartOnFileChange: false,
    singleRun: true,
  });
};
