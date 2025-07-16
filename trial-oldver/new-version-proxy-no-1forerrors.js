// scanner.js

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
const stealth = StealthPlugin();
puppeteer.use(stealth);

const SCRAPER_API_PROXY_HOST = 'proxy-server.scraperapi.com:8001';
const SCRAPER_API_PROXY_USER = 'scraperapi';
const SCRAPER_API_PROXY_PASS = '81bef26341bebf35a9990bd0fe588682';



let browser;
async function launchBrowser(proxy = null) {
  if (browser) {
    try {
      await browser.close();
    } catch (_) {}
  }

  const args = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-web-security',
    '--disable-features=IsolateOrigins,site-per-process',
    '--ignore-certificate-errors',
    '--ignore-ssl-errors'
  ];

  if (proxy) {
    args.push(`--proxy-server=${proxy}`);
  }

  browser = await puppeteer.launch({
    headless: 'new',
    args,
    protocolTimeout: 120000
  });
}

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

  await delay(250);
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await delay(500);

  try{
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
          const rawAction = form.action || '';
          const actionStr = typeof rawAction === 'string' ? rawAction : String(rawAction);

          const isExternal = actionStr && !actionStr.includes(location.hostname);
          const isBinary = suspiciousExtensions.some(ext => actionStr.endsWith(ext));

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
        const externalLinks = [...document.querySelectorAll('a')].filter(a => typeof a.href === 'string' && !a.href.includes(location.hostname)).length;
        const embeddedObjects = document.querySelectorAll('embed, object').length;
        const suspiciousInlineStyles = [...document.querySelectorAll('*')].filter(el => /display\s*:\s*none|visibility\s*:\s*hidden/i.test(el.getAttribute('style') || '')).length;
        const suspiciousLinkCount = [...document.querySelectorAll('a')].filter(a => typeof a.href === 'string' && /\.php|\.exe|base64/i.test(a.href)).length;
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
  } catch (e) {
      throw new Error(`Failed to extract features: ${e.message}`);
    }
  };

async function tryScan(page, url, sslBypass, userAgent) {
  const client = await page.target().createCDPSession();
  if (sslBypass && url.startsWith('https://')) {
    await client.send('Security.setIgnoreCertificateErrors', { ignore: true });
  }
  return await getDomFeatures(page, url, userAgent);
}

export const scanUrls = async (urls, concurrencyLimit = 15) => {
  const limit = pLimit(concurrencyLimit);
  const results = {};
  const errorLog = [];

  await launchBrowser(); // Launch default browser (no proxy)

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
      'net::ERR_CONNECTION_CLOSED',
      'net::ERR_BLOCKED_BY_CLIENT',
      'net::ERR_CONNECTION_REFUSED',
      'ERR_SSL_VERSION_OR_CIPHER_MISMATCH'
    ];

    let userAgent = new UserAgent().toString();
    let errorMsgs = [];
    let proxyNeeded = false;

    for (let { url, sslBypass } of versions) {
      let page;
      try {
        page = await browser.newPage();
        // Short delay to stabilize
        await delay(500);

        // Block other unnecessary data
        await page.setRequestInterception(true);
        page.on('request', req => {
          const type = req.resourceType();
          if (["image", "stylesheet", "font"].includes(type)) return req.abort();
          req.continue();
        });

        // For the system navigation
        page.on('framenavigated', frame => {
          console.warn(`⚠️ Frame navigated: ${frame.url()}`);
        });

        // Scanning of the data
        const features = await tryScan(page, url, sslBypass, userAgent);
        await delay(1000 + Math.random() * 500);
        await page.close();

        // Return the gathered data
        return { features, 
          finalUrl: url, 
          sslBypassUsed: 
          sslBypass ? 1 : 0, 
          usedProxy: false, 
          userAgent 
        };

      } catch (err) {
        errorMsgs.push(`${sslBypass ? 'SSL Bypass' : 'Try'}: ${err.message} at ${url}`);
        if (err.message.includes('Protocol error: Connection closed.')) {
          console.warn(`🔁 Relaunching browser due to closed connection at ${url}`);
          await delay(3000);
          await launchBrowser();
        }
        
        if (proxyRetryErrors.some(e => err.message.includes(e))) proxyNeeded = true;
      } finally {
        if (page) await page.close().catch(() => {});
      }
    }

    // If all default scans failed and proxy-related error found
    if (proxyNeeded) {
      console.warn(`🌐 Retrying ${originalUrl} with ScraperAPI proxy`);
      const proxyArgs = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--ignore-certificate-errors',
        '--ignore-ssl-errors',
        `--proxy-server=${SCRAPER_API_PROXY_HOST}`
      ];

      const proxyBrowser = await puppeteer.launch({ headless: 'new', args: proxyArgs });

      for (let { url, sslBypass } of versions) {
        let page;
        try {
          page = await proxyBrowser.newPage();

          await page.authenticate({
            username: SCRAPER_API_PROXY_USER,
            password: SCRAPER_API_PROXY_PASS
          });
          
          await delay(200);
          await page.setRequestInterception(true);
          page.on('request', req => {
            if (["image", "stylesheet", "font"].includes(req.resourceType())) req.abort();
            else req.continue();
          });

          const features = await tryScan(page, url, sslBypass, userAgent);
          await delay(1000 + Math.random() * 500);
          await page.close();
          await proxyBrowser.close();
          return { features, finalUrl: url, sslBypassUsed: sslBypass ? 1 : 0, usedProxy: true, userAgent };

        } catch (err) {
          errorMsgs.push(`Proxy ${sslBypass ? 'SSL Bypass' : 'Try'}: ${err.message} at ${url}`);
        } finally {
          if (page) await page.close().catch(() => {});
        }
      }

      await proxyBrowser.close();
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
          usedProxy: Number(usedProxy),
          finalUrlTried: finalUrl,
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
    if (browser) await browser.close();
  } catch (_) {}

  await writeResultsToCsv(getCsvFilePath(), results);
  return results;
};
