async function scanWithRetry(originalUrl) {
  const baseUrl = originalUrl.replace('://www.', '://');
  const versions = [
    { url: originalUrl, sslBypass: false },
    { url: baseUrl, sslBypass: false },
    { url: originalUrl, sslBypass: true },
    { url: baseUrl, sslBypass: true }
  ];

  let result = null;
  let errorMsgs = [];
  let userAgent = new UserAgent().toString();
  let networkChangedRetries = 0; // Reset per scan

  for (const { url, sslBypass } of versions) {
    let page;

    try {
      page = await pageLimit(() => browser.newPage());

      await page.setUserAgent(userAgent);
      await page.setRequestInterception(true);
      page.on('request', req => {
        const type = req.resourceType();
        if (["image", "stylesheet", "font", "media"].includes(type)) {
          req.abort();
        } else {
          req.continue();
        }
      });

      if (sslBypass) {
        await page.setBypassCSP(true);
      }

      const features = await tryScan(page, url, sslBypass, userAgent);
      result = {
        features,
        finalUrl: url,
        sslBypassUsed: sslBypass ? 1 : 0,
        usedProxy: false,
        userAgent
      };
      await page.close();
      break; // success — exit loop

    } catch (err) {
      if (err.message.includes('ERR_NETWORK_CHANGED')) {
        if (networkChangedRetries < 1) {
          console.warn(`⚠️ Network change detected for ${url}, retrying once...`);
          networkChangedRetries++;
          await delay(5000); // Let network stabilize
          continue; // retry same URL
        } else {
          console.error(`❌ Already retried after network change. Giving up on ${url}`);
        }
      }
      errorMsgs.push(`- ${url} ${sslBypass ? '(bypass)' : ''}: ${err.message}`);
    } finally {
      if (page) await page.close().catch(() => {});
    }
  }

  // 🔄 Fallback to ScraperAPI proxy if all above failed
  if (!result && proxyNeeded) {
    console.warn(`🌐 Retrying ${originalUrl} using ScraperAPI URL proxy`);

    return await proxyLimit(async () => {
      for (let { url } of versions) {
        let page;
        try {
          const scraperApiUrl = `http://api.scraperapi.com/?api_key=${SCRAPER_API_PROXY_PASS}&url=${encodeURIComponent(url)}`;
          page = await pageLimit(() => browser.newPage());

          await page.setUserAgent(userAgent);
          await page.setRequestInterception(true);
          page.on('request', req => {
            const type = req.resourceType();
            if (["image", "stylesheet", "font", "media"].includes(type)) {
              req.abort();
            } else {
              req.continue();
            }
          });

          const features = await tryScan(page, scraperApiUrl, false, userAgent);
          await delay(1000 + Math.random() * 500);

          await page.close();
          return {
            features,
            finalUrl: url,
            sslBypassUsed: 0,
            usedProxy: true,
            userAgent
          };

        } catch (err) {
          errorMsgs.push(`- ScraperAPI (${url}): ${err.message}`);
          if (page) await page.close().catch(() => {});
        }
      }
      throw new Error(`All proxy attempts failed:\n${errorMsgs.join('\n')}`);
    });
  }

  // ❌ Nothing worked
  if (!result) {
    throw new Error(`Scan failed for ${originalUrl}:\n${errorMsgs.join('\n')}`);
  }

  return result;
}
