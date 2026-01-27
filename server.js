require('dotenv').config();
const fastify = require('fastify')({ logger: false, trustProxy: true });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');
const rateLimit = require('@fastify/rate-limit');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

oracledb.thin = true;
oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT; // Facilita a leitura dos resultados

fastify.register(rateLimit, {
  max: 10, // Aumentei um pouco para não travar o uso legítimo
  timeWindow: '1 minute',
  errorResponseBuilder: () => ({
    success: false,
    message: 'Muitas requisições. Aguarde um momento.'
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

// ==========================================
// ROTA 1: VALIDAR SETUP (PRIMEIRO ACESSO)
// ==========================================
fastify.get('/api/auth/setup-check/:token', async (request, reply) => {
    const { token } = request.params;
    let connection;

    try {
        connection = await getDbConnection();
        
        // Verifica se o token existe, não expirou e o MFA não foi feito
        const sql = `SELECT USER_ID, EMAIL_LOGIN, MFA_SECRET, NOME_EXIBICAO 
                     FROM ASYNCX_USERS 
                     WHERE RESET_TOKEN = :token 
                     AND RESET_EXPIRATION > CURRENT_TIMESTAMP 
                     AND MFA_SETUP_COMPLETE = 0`;

        const result = await connection.execute(sql, { token });

        if (result.rows.length === 0) {
            return reply.status(400).send({ success: false, message: "Link inválido ou expirado." });
        }

        const user = result.rows[0];

        // Gerar a URL para o Google Authenticator
        const otpauth_url = speakeasy.otpauthURL({
            secret: user.MFA_SECRET,
            label: `ASYNCX:${user.EMAIL_LOGIN}`,
            issuer: 'ASYNCX',
            encoding: 'base32'
        });

        // Gerar QR Code em Base64
        const qrCodeDataURL = await QRCode.toDataURL(otpauth_url);

        return {
            success: true,
            nome: user.NOME_EXIBICAO,
            email: user.EMAIL_LOGIN,
            qrCode: qrCodeDataURL
        };

    } catch (err) {
        return reply.status(500).send({ success: false, message: "Erro interno no servidor" });
    } finally {
        if (connection) await connection.close();
    }
});

// ==========================================
// ROTA 2: FINALIZAR CADASTRO (SALVAR SENHA)
// ==========================================
fastify.post('/api/auth/setup-finalize', async (request, reply) => {
    const { token, senha, mfaToken } = request.body;
    let connection;

    try {
        connection = await getDbConnection();

        // 1. Busca o segredo MFA para validar o código digitado
        const userRes = await connection.execute(
            `SELECT USER_ID, MFA_SECRET FROM ASYNCX_USERS WHERE RESET_TOKEN = :token`, 
            { token }
        );

        if (userRes.rows.length === 0) throw new Error("Usuário não encontrado.");
        
        const user = userRes.rows[0];

        // 2. Valida se o código do Google Authenticator está correto
        const verified = speakeasy.totp.verify({
            secret: user.MFA_SECRET,
            encoding: 'base32',
            token: mfaToken
        });

        if (!verified) {
            return reply.status(400).send({ success: false, message: "Código do Authenticator inválido." });
        }

        // 3. Atualiza senha, marca MFA como completo e limpa o token de reset
        await connection.execute(
            `UPDATE ASYNCX_USERS SET 
             SENHA_HASH = :senha, 
             MFA_SETUP_COMPLETE = 1, 
             RESET_TOKEN = NULL, 
             STATUS_MONITORAMENTO = 'ATIVO'
             WHERE USER_ID = :id`,
            { senha, id: user.USER_ID },
            { autoCommit: true }
        );

        return { success: true, message: "Conta ativada com sucesso!" };

    } catch (err) {
        return reply.status(500).send({ success: false, message: err.message });
    } finally {
        if (connection) await connection.close();
    }
});

// A ROTA DE LOGIN E TELEGRAM CONTINUAM ABAIXO...
// (Mantenha o restante do seu código original aqui)

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