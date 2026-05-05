const DEFAULT_BASE = 'https://localhost:18443';

function getBaseUrl() {
  return process.env.WG_BASE || DEFAULT_BASE;
}

function getLaunchOptions() {
  var opts = {
    headless: true,
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
  };
  if (process.env.WG_BROWSER_PATH) opts.executablePath = process.env.WG_BROWSER_PATH;
  return opts;
}

async function launchBrowser(chromium) {
  return chromium.launch(getLaunchOptions());
}

module.exports = {
  BASE: getBaseUrl(),
  FAIL_ON_SKIP: process.env.WG_FAIL_ON_SKIP === '1',
  launchBrowser: launchBrowser,
};
