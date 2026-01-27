require('dotenv').config();
const fastify = require('fastify')({ logger: false, trustProxy: true });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');
const rateLimit = require('@fastify/rate-limit');

oracledb.thin = true;

fastify.register(rateLimit, {
  max: 1,
  timeWindow: '5 minutes',
  errorResponseBuilder: () => ({
    success: false,
    message: 'Aguarde 5 minutos antes de enviar uma nova mensagem.'
  })
});

fastify.register(cors, { 
  origin: ["https://gilson-ferrer.github.io", "https://www.asyncx.com.br", "https://asyncx.com.br"],
  methods: ["POST", "GET"]
});

async function getDbConnection() {
  return await oracledb.getConnection({
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    connectionString: process.env.DB_CONNECTION_STRING.trim()
  });
}

// ROTA DE LOGIN (NOVA)
fastify.post('/api/login', async (request, reply) => {
  const { email, senha } = request.body;
  let connection;

  try {
    connection = await getDbConnection();
    // Buscamos os campos necessários para o Painel de Saúde
    const result = await connection.execute(
      `SELECT NOME, TIPO_SERVICO, MONITORAMENTO_STATUS, LINK_LAUDO, LINK_BOLETO 
       FROM LEADS_SITE 
       WHERE EMAIL = :email AND SENHA = :senha`,
      { email, senha }
    );

    if (result.rows.length === 0) {
      return reply.status(401).send({ success: false, message: "E-mail ou senha incorretos." });
    }

    const user = result.rows[0];
    return {
      success: true,
      data: {
        nome: user[0],
        servico: user[1],
        status: user[2],
        linkLaudo: user[3],
        linkBoleto: user[4]
      }
    };
  } catch (err) {
    return reply.status(500).send({ success: false, message: "Erro na autenticação" });
  } finally {
    if (connection) await connection.close();
  }
});

// ROTA DE CONTATO ATUALIZADA: FOCO EXCLUSIVO NO TELEGRAM
fastify.post('/api/telegram-notify', async (request, reply) => {
    const { nome, email, mensagem } = request.body;

    // 1. Verificação de Variáveis de Ambiente
    const token = process.env.TELEGRAM_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    if (!token || !chatId) {
        console.error("ERRO: Credenciais do Telegram não configuradas no Render.");
        return reply.status(500).send({ success: false, message: "Erro de configuração no servidor." });
    }

    try {
        // 2. Preparação da Mensagem
        const telegramUrl = `https://api.telegram.org/bot${token}/sendMessage`;
        const textoTelegram = `🚀 *NOVO CONTATO ASYNCX*\n\n` +
                              `*Nome:* ${nome}\n` +
                              `*E-mail:* ${email}\n` +
                              `*Mensagem:* ${mensagem}\n\n` +
                              `_Enviado via Website_`;

        // 3. Disparo Assíncrono para o Telegram
        const response = await fetch(telegramUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: chatId,
                text: textoTelegram,
                parse_mode: 'Markdown'
            })
        });

        if (!response.ok) {
            throw new Error(`Telegram API Error: ${response.status}`);
        }

        // 4. Resposta para o Frontend (Sem tocar no Banco por enquanto)
        return { 
            success: true, 
            message: 'Protocolo ASYNCX enviado com sucesso para a central!' 
        };

    } catch (err) {
        console.error("Falha no processo de notificação:", err.message);
        return reply.status(500).send({ 
            success: false, 
            message: "Falha ao processar mensagem. Tente o WhatsApp." 
        });
    }
});

fastify.get('/', async () => ({ status: 'online', service: 'ASYNCX-API' }));

const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 10000, host: '0.0.0.0' });
  } catch (err) {
    process.exit(1);
  }
};
start();