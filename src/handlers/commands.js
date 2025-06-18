import { sendMessage } from '../services/telegram.js';
import { VirusTotalAPI } from '../services/virustotal.js';
import { handleFileUpload } from './fileHandler.js';
import { handleUrlScan } from './urlHandler.js';
import {
  formatFileReport,
  formatUrlReport,
  formatIpReport,
  formatDomainReport
} from '../utils/helpers.js';

// Validasi input
function isValidIP(ip) {
  const ipv4 = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
  const ipv6 = /^((?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|::1)$/;
  return ipv4.test(ip) || ipv6.test(ip);
}

function isValidDomain(domain) {
  const domainRegex = /^(?!:\/\/)([a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+)$/;
  return domainRegex.test(domain);
}

function isValidHash(hash) {
  const md5 = /^[a-fA-F0-9]{32}$/;
  const sha1 = /^[a-fA-F0-9]{40}$/;
  const sha256 = /^[a-fA-F0-9]{64}$/;
  return md5.test(hash) || sha1.test(hash) || sha256.test(hash);
}

export async function handleTelegramUpdate(update, env) {
  try {
    if (update.message) {
      await handleMessage(update.message, env);
    } else if (update.callback_query) {
      // Implementasi callback query jika diperlukan
    }
    return new Response('OK', { status: 200 });
  } catch (error) {
    console.error('Error handling update:', error);
    return new Response('Error', { status: 500 });
  }
}

async function handleMessage(message, env) {
  const chatId = message.chat.id;
  const text = message.text?.trim() || '';
  const vt = new VirusTotalAPI(env.VIRUSTOTAL_API_KEY);

  // Jika pesan berupa perintah
  if (text.startsWith('/')) {
    await handleCommand(message, env, vt);
    return;
  }

  // Jika ada file / dokumen
  if (message.document || message.photo) {
    await handleFileUpload(message, env, vt);
    return;
  }

  // Jika pesan adalah URL
  if (text.startsWith('http://') || text.startsWith('https://')) {
    await handleUrlScan(message, env, vt);
    return;
  }

  // Jika pesan adalah IP
  if (isValidIP(text)) {
    await handleIpScan(message, env, vt);
    return;
  }

  // Jika pesan adalah domain
  if (isValidDomain(text)) {
    await handleDomainScan(message, env, vt);
    return;
  }

  // Jika pesan adalah hash
  if (isValidHash(text)) {
    await handleHashLookup(message, env, vt);
    return;
  }

  await sendMessage(chatId, 'Pesan tidak dikenali. Gunakan /help untuk melihat daftar perintah.', env);
}

async function handleCommand(message, env, vt) {
  const chatId = message.chat.id;
  const text = message.text.trim();
  const parts = text.split(' ');
  const command = parts[0];
  const args = parts.slice(1);

  switch (command) {
    case '/start':
      await sendMessage(chatId, `
<b>VirusTotal Bot 🤖</b>

Selamat datang! Saya dapat membantu Anda memindai file, URL, IP, domain, dan hash menggunakan VirusTotal API.

<b>Perintah Tersedia:</b>
/help - Tampilkan bantuan
/scan_url [URL] - Pindai URL
/scan_ip [IP] - Laporan IP
/scan_domain [domain] - Laporan domain
/search [kata kunci] - Cari di database VirusTotal
/hash [hash] - Cari file berdasarkan hash

Anda juga bisa mengirim file, URL, IP, domain, atau hash langsung.
      `, env);
      break;

    case '/help':
      await sendMessage(chatId, `
<b>Panduan Penggunaan 🔍</b>

<b>Memindai File:</b> Kirim file (max 32MB) untuk dipindai.

<b>Memindai URL:</b> Gunakan /scan_url [URL] atau kirim URL langsung.

<b>Laporan IP:</b> Gunakan /scan_ip [IP] atau kirim IP langsung.

<b>Laporan Domain:</b> Gunakan /scan_domain [domain] atau kirim domain langsung.

<b>Cari berdasarkan Hash:</b> Gunakan /hash [MD5|SHA1|SHA256] atau kirim hash langsung.

<b>Pencarian:</b> Gunakan /search [kata kunci] untuk mencari VirusTotal.

Contoh:
/scan_url https://example.com
/scan_ip 8.8.8.8
/scan_domain google.com
/search malware.exe
/hash d41d8cd98f00b204e9800998ecf8427e
      `, env);
      break;

    case '/scan_url':
      if (args.length === 0) {
        await sendMessage(chatId, 'Mohon masukkan URL yang ingin dipindai.\nContoh: /scan_url https://example.com', env);
        return;
      }
      await handleUrlScan({ chat: { id: chatId }, text: args[0] }, env, vt);
      break;

    case '/scan_ip':
      if (args.length === 0) {
        await sendMessage(chatId, 'Mohon masukkan IP untuk dicari.\nContoh: /scan_ip 8.8.8.8', env);
        return;
      }
      await handleIpScan({ chat: { id: chatId }, text: args[0] }, env, vt);
      break;

    case '/scan_domain':
      if (args.length === 0) {
        await sendMessage(chatId, 'Mohon masukkan domain untuk dicari.\nContoh: /scan_domain google.com', env);
        return;
      }
      await handleDomainScan({ chat: { id: chatId }, text: args[0] }, env, vt);
      break;

    case '/search':
      if (args.length === 0) {
        await sendMessage(chatId, 'Mohon masukkan kata kunci pencarian.\nContoh: /search malware.exe', env);
        return;
      }
      await handleSearch({ chat: { id: chatId }, text: args.join(' ') }, env, vt);
      break;

    case '/hash':
      if (args.length === 0) {
        await sendMessage(chatId, 'Mohon masukkan hash file.\nContoh: /hash d41d8cd98f00b204e9800998ecf8427e', env);
        return;
      }
      await handleHashLookup({ chat: { id: chatId }, text: args[0] }, env, vt);
      break;

    default:
      await sendMessage(chatId, 'Perintah tidak dikenal. Gunakan /help untuk melihat daftar perintah yang tersedia.', env);
  }
}

async function handleIpScan(message, env, vt) {
  const chatId = message.chat.id;
  const ip = message.text.trim();

  await sendMessage(chatId, '🔍 Memproses laporan IP...', env);

  try {
    const result = await vt.getIpReport(ip);
    if (result.error) {
      await sendMessage(chatId, `❌ Error: ${result.error.message}`, env);
      return;
    }
    const report = formatIpReport(result.data);
    await sendMessage(chatId, report, env);
  } catch (error) {
    await sendMessage(chatId, '❌ Terjadi kesalahan saat mengambil laporan IP. Silakan coba lagi nanti.', env);
  }
}

async function handleDomainScan(message, env, vt) {
  const chatId = message.chat.id;
  const domain = message.text.trim();

  await sendMessage(chatId, '🔍 Memproses laporan domain...', env);

  try {
    const result = await vt.getDomainReport(domain);
    if (result.error) {
      await sendMessage(chatId, `❌ Error: ${result.error.message}`, env);
      return;
    }
    const report = formatDomainReport(result.data);
    await sendMessage(chatId, report, env);
  } catch (error) {
    await sendMessage(chatId, '❌ Terjadi kesalahan saat mengambil laporan domain. Silakan coba lagi nanti.', env);
  }
}

async function handleHashLookup(message, env, vt) {
  const chatId = message.chat.id;
  const hash = message.text.trim();

  await sendMessage(chatId, '🔍 Mencari laporan hash...', env);

  try {
    const result = await vt.getFileReport(hash);
    if (result.error) {
      await sendMessage(chatId, `❌ Error: ${result.error.message}`, env);
      return;
    }
    const report = formatFileReport(result.data);
    await sendMessage(chatId, report, env);
  } catch (error) {
    await sendMessage(chatId, '❌ Terjadi kesalahan saat mencari hash. Silakan coba lagi nanti.', env);
  }
}

async function handleSearch(message, env, vt) {
  const chatId = message.chat.id;
  const query = message.text.trim();

  await sendMessage(chatId, `🔍 Mencari di VirusTotal untuk "${query}"...`, env);

  try {
    const result = await vt.search(query);
    if (result.error) {
      await sendMessage(chatId, `❌ Error: ${result.error.message}`, env);
      return;
    }
    if (!result.data || result.data.length === 0) {
      await sendMessage(chatId, 'Tidak ditemukan hasil.', env);
      return;
    }
    let responseText = `<b>Hasil pencarian untuk "${query}":</b>\n\n`;
    for (let i = 0; i < Math.min(result.data.length, 5); i++) {
      const item = result.data[i];
      responseText += `• <b>${item.type}</b>: ${item.id}\n`;
    }
    await sendMessage(chatId, responseText, env);
  } catch (error) {
    await sendMessage(chatId, '❌ Terjadi kesalahan saat pencarian. Silakan coba lagi nanti.', env);
  }
}

export {
  handleMessage,
  handleCommand,
  handleIpScan,
  handleDomainScan,
  handleHashLookup,
  handleSearch,
  handleTelegramUpdate
};

