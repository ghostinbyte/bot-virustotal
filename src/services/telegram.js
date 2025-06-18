export async function sendMessage(chatId, text, env, options = {}) {
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
  
  const payload = {
    chat_id: chatId,
    text: text,
    parse_mode: 'HTML',
    ...options
  };
  
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  
  return await response.json();
}

export async function sendDocument(chatId, document, caption, env) {
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendDocument`;
  
  const formData = new FormData();
  formData.append('chat_id', chatId);
  formData.append('document', document);
  if (caption) formData.append('caption', caption);
  
  const response = await fetch(url, {
    method: 'POST',
    body: formData
  });
  
  return await response.json();
}

export async function setWebhook(env) {
  const webhookUrl = `${env.WORKER_URL}/webhook`;
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/setWebhook`;
  
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: webhookUrl })
  });
  
  const result = await response.json();
  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json' }
  });
}
