import path from 'path';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import pLimit from 'p-limit';
import {
  writeResultsToCsv,
  writeErrorLogToCsv,
  getCsvFilePath
} from './csv-utils.js';
import UserAgent from 'user-agents';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
puppeteer.use(StealthPlugin());


export const getDomFeatures = async (page, url, userAgent) => {
  try {
    if (!page.isClosed()) {
      await page.setUserAgent(userAgent);
    }
  } catch (err) {
    console.warn(`⚠️ Failed to set User-Agent: ${err.message}`);
  }

  await page.setViewport({ width: 1366, height: 768 });
  await page.setExtraHTTPHeaders({ 'Accept-Language': 'en-US,en;q=0.9' });
  await page.setJavaScriptEnabled(true);
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 });

  const features = await page.evaluate(() => {
    const tagCounts = () => {
      const counts = {};
      const els = document.querySelectorAll('*');
      els.forEach(el => {
        const tag = el.tagName;
        counts[tag] = (counts[tag] || 0) + 1;
      });
      return { totalNodes: els.length, uniqueTags: Object.keys(counts).length };
    };
    const countInlineJS = () => {
      let handlers = 0, hrefJS = 0;
      document.querySelectorAll('*').forEach(el => {
        handlers += [...el.attributes].filter(a => a.name.startsWith('on')).length;
        if (typeof el.href === 'string' && el.href.startsWith('javascript:')) hrefJS++;
      });
      return { inlineEventHandlers: handlers, javascriptHref: hrefJS };
    };
    const countLoginForms = () => {
      const forms = document.forms;
      let loginCount = 0;
      let externalFormActionBinary = 0;
      let externalFormActionNonBinary = 0;

      const suspiciousExtensions = ['.php', '.exe', '.bin', '.dll', '.js'];

      [...forms].forEach(form => {
        const hasPassword = [...form.elements].some(el => el.type === 'password');
        const action = form.action || '';
        const isExternal = action && !action.includes(location.hostname);
        const isBinary = suspiciousExtensions.some(ext => action.endsWith(ext));

        if (hasPassword) loginCount++;
        if (hasPassword && isExternal && isBinary) externalFormActionBinary++;
        if (hasPassword && isExternal && !isBinary) externalFormActionNonBinary++;
      });

      const passwordCount = document.querySelectorAll('input[type="password"]').length;

      return {
        loginFormCount: loginCount,
        passwordFieldCount: passwordCount,
        externalFormActionBinary,
        externalFormActionNonBinary
      };
    };
    const detectSuspiciousKeywords = () => {
      const keywords = ['eval(', 'document.write', 'atob(', 'setTimeout(', 'setInterval(', 'iframe', 'unescape'];
      let suspicious = 0;
      document.querySelectorAll('script').forEach(s => {
        if (keywords.some(k => s.textContent.includes(k))) suspicious++;
      });
      return { suspiciousKeywords: suspicious };
    };
    const countHiddenIframes = () => {
      let hidden = 0;
      document.querySelectorAll('iframe').forEach(iframe => {
        const style = window.getComputedStyle(iframe);
        if (style.display === 'none' || style.visibility === 'hidden') hidden++;
      });
      return { hiddenIframeCount: hidden };
    };
    const countSuspiciousScripts = () => {
      const suspiciousSrc = ['.php', 'eval', 'base64', 'unescape'];
      let suspicious = 0;
      document.querySelectorAll('script').forEach(script => {
        if (suspiciousSrc.some(word => (script.src || '').includes(word))) suspicious++;
      });
      return { suspiciousScriptTags: suspicious };
    };
    const additionalFeatures = () => {
      const metaTags = document.querySelectorAll('meta').length;
      const scripts = [...document.querySelectorAll('script')];
      const externalScripts = scripts.filter(s => s.src).length;
      const inlineScripts = scripts.length - externalScripts;
      const externalLinks = [...document.querySelectorAll('a')].filter(a => a.href && !a.href.includes(location.hostname)).length;
      const embeddedObjects = document.querySelectorAll('embed, object').length;
      const suspiciousInlineStyles = [...document.querySelectorAll('*')].filter(el => /display\s*:\s*none|visibility\s*:\s*hidden/i.test(el.getAttribute('style') || '')).length;
      const suspiciousLinkCount = [...document.querySelectorAll('a')].filter(a => /\.php|\.exe|base64/i.test(a.href || '')).length;
      return {
        metaTagCount: metaTags,
        externalScriptCount: externalScripts,
        inlineScriptCount: inlineScripts,
        externalLinkCount: externalLinks,
        embeddedObjectCount: embeddedObjects,
        suspiciousInlineStyleCount: suspiciousInlineStyles,
        suspiciousLinkCount
      };
    };

    return {
      ...tagCounts(),
      ...countInlineJS(),
      ...countLoginForms(),
      ...detectSuspiciousKeywords(),
      ...countHiddenIframes(),
      ...countSuspiciousScripts(),
      ...additionalFeatures(),
      scriptCount: document.scripts.length,
      linkCount: document.links.length,
      iframeCount: document.querySelectorAll('iframe').length,
      formCount: document.forms.length
    };
  });

  return features;
};

export const scanUrls = async (urls, concurrencyLimit = 5) => {
  const limit = pLimit(concurrencyLimit);
  const results = {};
  const errorLog = [];

  const SCRAPER_API_PROXY = 'scraperapi:APIKEY@proxy-server.scraperapi.com:8001';

  let defaultBrowser;
  await launchDefaultBrowser(); // start shared browser for non-proxy scans

  async function launchDefaultBrowser() {
    if (defaultBrowser) {
      try { await defaultBrowser.close(); } catch (_) {}
    }
    defaultBrowser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--ignore-certificate-errors',
        '--ignore-ssl-errors'
      ]
    });
  }

  async function launchProxyBrowser() {
    return await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--ignore-certificate-errors',
        '--ignore-ssl-errors',
        `--proxy-server=${SCRAPER_API_PROXY}`
      ]
    });
  }

  async function tryScan(browser, url, sslBypass, userAgent) {
    const page = await browser.newPage();
    await delay(200);
    await page.setRequestInterception(true);
    page.on('request', req => {
      if (["image", "stylesheet", "font"].includes(req.resourceType())) req.abort();
      else req.continue();
    });

    const client = await page.target().createCDPSession();
    if (sslBypass && url.startsWith('https://')) {
      await client.send('Security.setIgnoreCertificateErrors', { ignore: true });
    }

    const features = await getDomFeatures(page, url, userAgent);
    await delay(1000 + Math.random() * 500);
    await page.close();
    return features;
  }

  async function scanWithRetry(originalUrl) {
    const baseUrl = originalUrl.replace('://www.', '://');
    const versions = [
      { url: originalUrl, sslBypass: false },
      { url: baseUrl, sslBypass: false },
      { url: originalUrl, sslBypass: true },
      { url: baseUrl, sslBypass: true }
    ];

    const proxyRetryErrors = [
      'net::ERR_NAME_NOT_RESOLVED',
      'net::ERR_CONNECTION_TIMED_OUT',
      'net::ERR_CONNECTION_RESET',
      'net::ERR_CONNECTION_CLOSED'
    ];

    let stealthConfigured = false;
    let retried = false;
    let usedProxy = false;
    let errorMsgs = [];
    let attemptCount = 0;

    while (attemptCount < versions.length) {
      const { url, sslBypass } = versions[attemptCount++];
      const userAgent = new UserAgent().toString();
      let localBrowser = null;

      try {
        const currentBrowser = usedProxy ? (localBrowser = await launchProxyBrowser()) : defaultBrowser;
        const features = await tryScan(currentBrowser, url, sslBypass, userAgent);

        if (usedProxy && localBrowser) await localBrowser.close();
        return { features, finalUrl: url, sslBypassUsed: sslBypass ? 1 : 0, usedProxy, userAgent };

      } catch (err) {
        errorMsgs.push(`${sslBypass ? 'SSL Bypass' : 'Try'}: ${err.message} at ${url}`);

        if (!retried && err.message.includes('Protocol error: Connection closed.')) {
          console.warn(`🔁 Relaunching default browser due to closed connection at ${url}`);
          await delay(3000);
          await launchDefaultBrowser();
          retried = true;
          continue;
        }

        if (!usedProxy && proxyRetryErrors.some(msg => err.message.includes(msg))) {
          console.warn(`🌐 Retrying ${url} with ScraperAPI proxy`);
          if (!stealthConfigured) {
            const stealth = StealthPlugin();
            stealth.enabledEvasions.delete('user-agent-override');
            puppeteer.use(stealth);
            stealthConfigured = true;
          }
          usedProxy = true;
          attemptCount = 0; // restart attempts with proxy
          continue;
        }

        await delay(1000);
      } finally {
        if (usedProxy && localBrowser) {
          try { await localBrowser.close(); } catch (_) {}
        }
      }
    }

    throw new Error(errorMsgs.join(' | '));
  }

  const tasks = urls.map(({ url, label }) =>
    limit(async () => {
      try {
        console.log(`✅ Scanning: ${url}`);
        const { features, finalUrl, sslBypassUsed, usedProxy, userAgent } = await scanWithRetry(url);
        results[url] = {
          ...features,
          sslBypassUsed,
          usedProxy,
          finalUrlTried: finalUrl,
          userAgent,
          label
        };
      } catch (err) {
        console.error(`❌ Error scanning ${url}: ${err.message}`);
        results[url] = { error: err.message, label };
        errorLog.push({ url, error: err.message });
      }
    })
  );

  await Promise.all(tasks);

  try {
    if (defaultBrowser) await defaultBrowser.close();
  } catch (_) {}

  await writeResultsToCsv(getCsvFilePath(), results);
  if (errorLog.length > 0) await writeErrorLogToCsv(errorLog);

  return results;
};

