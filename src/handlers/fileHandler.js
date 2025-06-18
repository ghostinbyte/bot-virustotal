import { sendMessage, sendDocument } from '../services/telegram.js';
import { VirusTotalAPI } from '../services/virustotal.js';

export async function handleFileUpload(message, env, vt) {
  const chatId = message.chat.id;
  const fileId = message.document ? message.document.file_id : message.photo[message.photo.length - 1].file_id;

  // Mendapatkan file dari Telegram
  const fileResponse = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getFile?file_id=${fileId}`);
  const fileData = await fileResponse.json();

  if (!fileData.ok) {
    await sendMessage(chatId, '❌ Error retrieving file. Please try again.', env);
    return;
  }

  const filePath = fileData.result.file_path;
  const fileUrl = `https://api.telegram.org/file/bot${env.TELEGRAM_BOT_TOKEN}/${filePath}`;

  // Mengunduh file
  const fileBuffer = await fetch(fileUrl).then(res => res.arrayBuffer());

  // Memindai file menggunakan VirusTotal
  await sendMessage(chatId, '🔍 Scanning file...', env);
  try {
    const result = await vt.scanFile(fileBuffer, message.document.file_name || 'uploaded_file');
    const report = await vt.getFileReport(result.data.id);
    const formattedReport = formatFileReport(report.data);
    await sendMessage(chatId, formattedReport, env);
  } catch (error) {
    await sendMessage(chatId, '❌ Error scanning file. Please try again later.', env);
  }
}
