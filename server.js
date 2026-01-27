require('dotenv').config();
const fastify = require('fastify')({ logger: false, trustProxy: true });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');
const rateLimit = require('@fastify/rate-limit');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const bcrypt = require('bcrypt');
const saltRounds = 10;

oracledb.thin = true;
oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT; 

fastify.register(rateLimit, {
  max: 10,
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
        const sql = `SELECT USER_ID, EMAIL_LOGIN, MFA_SECRET, NOME_EXIBICAO 
                     FROM ASYNCX_USERS 
                     WHERE RESET_TOKEN = :token 
                     AND RESET_EXPIRATION > CURRENT_TIMESTAMP 
                     AND MFA_SETUP_COMPLETE = 0`;
        const result = await connection.execute(sql, { token });
        if (result.rows.length === 0) return reply.status(400).send({ success: false, message: "Link inválido ou expirado." });
        
        const user = result.rows[0];
        const otpauth_url = speakeasy.otpauthURL({
            secret: user.MFA_SECRET,
            label: `ASYNCX:${user.EMAIL_LOGIN}`,
            issuer: 'ASYNCX',
            encoding: 'base32'
        });
        const qrCodeDataURL = await QRCode.toDataURL(otpauth_url);
        return { success: true, nome: user.NOME_EXIBICAO, email: user.EMAIL_LOGIN, qrCode: qrCodeDataURL };
    } catch (err) {
        return reply.status(500).send({ success: false, message: "Erro interno no servidor" });
    } finally {
        if (connection) await connection.close();
    }
});

// ==========================================
// ROTA 2: FINALIZAR CADASTRO (SALVAR SENHA COM HASH)
// ==========================================
fastify.post('/api/auth/setup-finalize', async (request, reply) => {
    const { token, senha, mfaToken } = request.body;
    let connection;
    try {
        connection = await getDbConnection();
        
        // 1. Localiza o usuário pelo token de ativação
        const userRes = await connection.execute(
            `SELECT USER_ID, MFA_SECRET FROM ASYNCX_USERS WHERE RESET_TOKEN = :token`, 
            { token }
        );
        
        if (userRes.rows.length === 0) throw new Error("Link de ativação inválido ou expirado.");
        const user = userRes.rows[0];

        // 2. Valida o MFA (Double Check de Segurança)
        const verified = speakeasy.totp.verify({
            secret: user.MFA_SECRET,
            encoding: 'base32',
            token: mfaToken
        });
        
        if (!verified) return reply.status(400).send({ success: false, message: "Código do Authenticator inválido." });

        // 3. GERAR O HASH DA SENHA (Defesa contra vazamento de banco)
        // O bcrypt gera o SALT automaticamente e inclui no hash final
        const senhaHasheada = await bcrypt.hash(senha, saltRounds);

        // 4. Salva o Hash e finaliza o setup
        await connection.execute(
            `UPDATE ASYNCX_USERS 
             SET SENHA_HASH = :senha, 
                 MFA_SETUP_COMPLETE = 1, 
                 RESET_TOKEN = NULL, 
                 STATUS_MONITORAMENTO = 'ATIVO' 
             WHERE USER_ID = :id`,
            { 
                senha: senhaHasheada, // Gravando o hash, não a senha limpa
                id: user.USER_ID 
            },
            { autoCommit: true }
        );

        return { success: true, message: "Segurança ASYNCX ativada com sucesso!" };
    } catch (err) {
        console.error("Erro Setup Finalize:", err.message);
        return reply.status(500).send({ success: false, message: err.message });
    } finally {
        if (connection) await connection.close();
    }
});

// ==========================================
// ROTA 3: LOGIN DEFINITIVO (COM MFA E BCRYPT)
// ==========================================
fastify.post('/api/login', async (request, reply) => {
    const { email, senha, mfaToken } = request.body;
    let connection;
    try {
        connection = await getDbConnection();
        const sql = `SELECT NOME_EXIBICAO, SENHA_HASH, MFA_SECRET, STATUS_MONITORAMENTO, QTD_DISPOSITIVOS 
                     FROM ASYNCX_USERS 
                     WHERE EMAIL_LOGIN = :email`;
        const result = await connection.execute(sql, { email });

        // 1. Verifica se o usuário existe
        if (result.rows.length === 0) {
            return reply.status(401).send({ success: false, message: "Credenciais inválidas." });
        }
        
        const user = result.rows[0];

        // 2. COMPARAÇÃO SEGURA: Texto plano vs Hash do Banco
        const senhaValida = await bcrypt.compare(senha, user.SENHA_HASH);
        if (!senhaValida) {
            return reply.status(401).send({ success: false, message: "Credenciais inválidas." });
        }

        // 3. Validação do MFA (Time-based One-Time Password)
        const verified = speakeasy.totp.verify({
            secret: user.MFA_SECRET,
            encoding: 'base32',
            token: mfaToken,
            window: 1 // Janela de tolerância para drift de tempo
        });

        if (!verified) {
            return reply.status(401).send({ success: false, message: "Código MFA inválido." });
        }

        // 4. Retorno de Sucesso
        return {
            success: true,
            data: {
                nome: user.NOME_EXIBICAO,
                status: user.STATUS_MONITORAMENTO,
                dispositivos: user.QTD_DISPOSITIVOS,
                servico: "Segurança Gerenciada ASYNCX"
            }
        };
    } catch (err) {
        console.error("Erro no Login:", err);
        return reply.status(500).send({ success: false, message: "Erro na autenticação" });
    } finally {
        if (connection) await connection.close();
    }
});

// ==========================================
// ROTA 4: NOTIFICAÇÃO TELEGRAM
// ==========================================
fastify.post('/api/telegram-notify', async (request, reply) => {
    const { nome, email, mensagem } = request.body;
    const token = process.env.TELEGRAM_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    if (!token || !chatId) return reply.status(500).send({ success: false, message: "Erro de configuração." });

    try {
        const telegramUrl = `https://api.telegram.org/bot${token}/sendMessage`;
        const textoTelegram = `🚀 *NOVO CONTATO ASYNCX*\n\n*Nome:* ${nome}\n*E-mail:* ${email}\n*Mensagem:* ${mensagem}`;

        await fetch(telegramUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, text: textoTelegram, parse_mode: 'Markdown' })
        });

        return { success: true, message: 'Protocolo enviado!' };
    } catch (err) {
        return reply.status(500).send({ success: false, message: "Falha ao notificar." });
    }
});

fastify.get('/', async () => ({ status: 'online', service: 'ASYNCX-API' }));

const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 10000, host: '0.0.0.0' });
    console.log("Servidor Backend Ativo");
  } catch (err) {
    process.exit(1);
  }
};

// ROTA: BUSCAR DADOS COMPLETOS (VERSÃO EXPANDIDA)
fastify.get('/api/user/dashboard-data/:email', async (request, reply) => {
    const { email } = request.params;
    let connection;

    try {
        connection = await getDbConnection();

        // 1. Busca Perfil Detalhado
        const userSql = `SELECT USER_ID, NOME_EXIBICAO, EMAIL_LOGIN, DOCUMENTO_IDENTIDADE, 
                         ENDERECO_COMPLETO, STATUS_MONITORAMENTO, QTD_DISPOSITIVOS, 
                         ASAAS_CUSTOMER_ID, ASAAS_SUBSCRIPTION_ID 
                         FROM ASYNCX_USERS WHERE EMAIL_LOGIN = :email`;
        const userRes = await connection.execute(userSql, { email });
        const user = userRes.rows[0];

        // 2. Busca Documentos
        const docsSql = `SELECT NOME_EXIBICAO, URL_PDF, TIPO_DOC, DATA_UPLOAD 
                         FROM ASYNCX_DOCUMENTS WHERE USER_ID = :id ORDER BY DATA_UPLOAD DESC`;
        const docsRes = await connection.execute(docsSql, { id: user.USER_ID });

        // 3. Busca Financeiro (Faturas Asaas)
        const billsSql = `SELECT ASAAS_PAYMENT_ID, VALOR, STATUS_PAGO, LINK_BOLETO, DATA_VENCIMENTO
                          FROM ASYNCX_BILLING WHERE USER_ID = :id ORDER BY DATA_VENCIMENTO DESC`;
        const billsRes = await connection.execute(billsSql, { id: user.USER_ID });

        return {
            success: true,
            perfil: user,
            documentos: docsRes.rows,
            financeiro: billsRes.rows
        };
    } catch (err) {
        return reply.status(500).send({ success: false, message: err.message });
    } finally {
        if (connection) await connection.close();
    }
});

// ==========================================
// NOVA ROTA: ALTERAR SENHA (COM HASHING)
// ==========================================
fastify.post('/api/user/change-password', async (request, reply) => {
    const { email, novaSenha } = request.body;
    let connection;
    try {
        connection = await getDbConnection();

        // 1. GERAR O HASH da nova senha
        // O saltRounds deve ser o mesmo usado nas outras rotas (10)
        const novaSenhaHasheada = await bcrypt.hash(novaSenha, 10);

        // 2. EXECUTAR O UPDATE com o hash
        const sql = `UPDATE ASYNCX_USERS 
                     SET SENHA_HASH = :senha 
                     WHERE EMAIL_LOGIN = :email`;

        const result = await connection.execute(
            sql,
            { senha: novaSenhaHasheada, email },
            { autoCommit: true }
        );

        // Verifica se o e-mail realmente existia e foi atualizado
        if (result.rowsAffected === 0) {
            return reply.status(404).send({ success: false, message: "Usuário não encontrado." });
        }

        return { success: true, message: "Senha alterada com sucesso e protegida!" };
    } catch (err) {
        console.error("Erro ao trocar senha:", err.message);
        return reply.status(500).send({ success: false, message: "Erro interno ao processar alteração." });
    } finally {
        if (connection) await connection.close();
    }
});

start();