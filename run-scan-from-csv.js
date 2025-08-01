// run-scan-from-csv.js
import path from 'path';
import fsSync from 'fs';
import { fileURLToPath } from 'url';
import { scanUrls } from './scanner_add.js';
import {
  readUrlsFromCsv,
  writeResultsToCsv,
  writeErrorLogToCsv,
  getCsvFilePath
} from './csv-utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const uploadsDir = path.join(__dirname, 'uploads');
const outputCsv = path.join(__dirname, 'outputs', 'dom-dataset.csv');
const errorCsv = path.join(__dirname, 'outputs', `errors-${Date.now()}.csv`);

function findLatestCsvFile(dir) {
  const files = fsSync.readdirSync(dir)
    .filter(file => file.endsWith('.csv'))
    .map(file => ({
      file,
      time: fsSync.statSync(path.join(dir, file)).mtime.getTime()
    }))
    .sort((a, b) => b.time - a.time);

  return files.length > 0 ? path.join(dir, files[0].file) : null;
}


(async () => {
  const latestCsv = findLatestCsvFile(uploadsDir);
  if (!latestCsv) {
    console.error('❌ No CSV file found in uploads directory.');
    process.exit(1);
  }

  console.log(`📄 Found CSV: ${latestCsv}`);

  const urls = await readUrlsFromCsv(latestCsv);
  if (!urls.length) {
    console.warn('⚠️ No URLs found in the latest CSV.');
    process.exit(0);
  }

  const results = await scanUrls(urls);

  const errors = Object.entries(results)
    .filter(([, val]) => val.error)
    .map(([url, val]) => ({ url, error: val.error }));

  if (errors.length) {
    await writeErrorLogToCsv(errorCsv, errors);
    console.warn(`⚠️ Logged ${errors.length} errors to ${errorCsv}`);
  }

  console.log('✅ Scan complete. Results saved to dom-dataset.csv');
})();
