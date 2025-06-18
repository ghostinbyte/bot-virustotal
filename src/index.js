import { handleTelegramUpdate } from './handlers/commands.js';
import { setWebhook } from './services/telegram.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Handle webhook setup
    if (url.pathname === '/set-webhook') {
      return await setWebhook(env);
    }
    
    // Handle Telegram updates
    if (url.pathname === '/webhook' && request.method === 'POST') {
      const update = await request.json();
      return await handleTelegramUpdate(update, env);
    }
    
    return new Response('Bot is running!', { status: 200 });
  }
};
