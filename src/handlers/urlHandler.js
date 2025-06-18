import { sendMessage } from '../services/telegram.js';
import { VirusTotalAPI } from '../services/virustotal.js';
import { formatUrlReport } from '../utils/helpers.js';

export async function handleUrlScan(message, env, vt) {
  const chatId = message.chat.id;
  const url = message.text.trim();

  await sendMessage(chatId, '🔍 Scanning URL...', env);

  try {
    const scanResult = await vt.scanUrl(url);
    const analysisId = scanResult.data.id;

    // Mendapatkan hasil analisis
    const report = await vt.getUrlAnalysis(analysisId);
    const formattedReport = formatUrlReport(report.data);
    await sendMessage(chatId, formattedReport, env);
  } catch (error) {
    await sendMessage(chatId, '❌ Error scanning URL. Please try again later.', env);
  }
}
