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


const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
puppeteer.use(StealthPlugin());

let browser;

async function launchBrowser() {
  if (browser) {
    try {
      await browser.close();
    } catch (_) {}
  }

  browser = await puppeteer.launch({
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

export const getDomFeatures = async (page, url) => {
  await page.setUserAgent(new UserAgent().toString());
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
      const titleLength = document.title.length;
      const embeddedObjects = document.querySelectorAll('embed, object').length;
      const suspiciousInlineStyles = [...document.querySelectorAll('*')].filter(el => /display\s*:\s*none|visibility\s*:\s*hidden/i.test(el.getAttribute('style') || '')).length;
      const suspiciousLinkCount = [...document.querySelectorAll('a')].filter(a => /\.php|\.exe|base64/i.test(a.href || '')).length;
      return {
        metaTagCount: metaTags,
        externalScriptCount: externalScripts,
        inlineScriptCount: inlineScripts,
        externalLinkCount: externalLinks,
        titleLength,
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
  const results = [];
  const errorLog = [];

  await launchBrowser(); // ✅ start browser

  async function tryScan(page, url, ignoreHTTPSErrors = false) {
    const client = await page.target().createCDPSession();
    if (ignoreHTTPSErrors && url.startsWith('https://')) {
      await client.send('Security.setIgnoreCertificateErrors', { ignore: true });
    }
    return await getDomFeatures(page, url);
  }

  async function scanWithRetry(originalUrl) {
  let retried = false;

  while (true) {
    const baseUrl = originalUrl.replace('://www.', '://');
    const versions = [
      { url: originalUrl, sslBypass: false },
      { url: baseUrl, sslBypass: false },
      { url: originalUrl, sslBypass: true },
      { url: baseUrl, sslBypass: true }
    ];

    const errorMsgs = [];

    for (let i = 0; i < versions.length; i++) {
      const { url, sslBypass } = versions[i];
      let page;

      try {
        page = await browser.newPage();
        await page.setRequestInterception(true);
        page.on('request', req => {
          if (['image', 'stylesheet', 'font'].includes(req.resourceType())) req.abort();
          else req.continue();
        });

        const features = await tryScan(page, url, sslBypass);
        await delay(1000 + Math.random() * 500);
        await page.close();
        return { features, finalUrl: url, sslBypassUsed: sslBypass ? 1 : 0 };

      } catch (err) {
        errorMsgs.push(`${sslBypass ? 'SSL Bypass' : 'Try'}: ${err.message} at ${url}`);

        // 🔁 Relaunch browser and try whole thing again (once)
        if (!retried && err.message.includes('Protocol error: Connection closed.')) {
          console.warn(`🔁 Relaunching browser due to closed connection at ${url}`);
          await launchBrowser();
          retried = true;
          break; // restart whole scanWithRetry loop
        }

        await delay(1000);
      } finally {
        if (page) await page.close().catch(() => {});
      }
    }

    // If already retried and still failed
    if (retried) {
      throw new Error(errorMsgs.join(' | '));
    } else {
      retried = true;
    }
  }
}


  const tasks = urls.map(({ url, label }) =>
    limit(async () => {
      try {
        console.log(`✅ Scanning: ${url}`);
        const { features, finalUrl, sslBypassUsed } = await scanWithRetry(url);
        results[url] = {
          ...features,
          sslBypassUsed,
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
  await browser.close();

  await writeResultsToCsv(getCsvFilePath(), results);
  return results;
};
