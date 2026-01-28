require('dotenv').config();
const fastify = require('fastify')({ logger: false, trustProxy: true });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');
const rateLimit = require('@fastify/rate-limit');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET; 
const crypto = require('crypto');

const { Resend } = require('resend');
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

if (!resend) {
    console.warn("[AVISO] RESEND_API_KEY não configurada. O envio de e-mail não funcionará.");
}
// TEMPLATE MINIMALISTA (BRANCO E AZUL)
const templateEmail = (nome, link, titulo, corpo, textoBotao) => `
    <div style="background-color: #ffffff; color: #1e293b; padding: 40px; font-family: 'Segoe UI', Tahoma, sans-serif; text-align: center; border: 1px solid #e2e8f0; border-radius: 32px; max-width: 500px; margin: auto;">
        <h1 style="color: #2563eb; letter-spacing: 4px; font-weight: 800; margin-bottom: 5px; font-size: 24px;">ASYNCX</h1>
        <p style="color: #64748b; text-transform: uppercase; font-size: 9px; letter-spacing: 2px; margin-bottom: 30px; font-weight: bold;">${titulo}</p>
        
        <div style="margin: 20px 0; border-top: 1px solid #f1f5f9; border-bottom: 1px solid #f1f5f9; padding: 30px 0;">
            <p style="font-size: 15px; margin-bottom: 10px;">Olá, <strong style="color: #2563eb;">${nome}</strong>.</p>
            <p style="font-size: 13px; color: #475569; line-height: 1.6; margin-bottom: 25px;">${corpo}</p>
            
            <a href="${link}" style="display: inline-block; background-color: #2563eb; color: #ffffff; padding: 16px 32px; text-decoration: none; border-radius: 16px; font-weight: bold; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; box-shadow: 0 10px 15px -3px rgba(37, 99, 235, 0.3);">${textoBotao}</a>
        </div>
        
        <p style="font-size: 10px; color: #94a3b8; line-height: 1.4;">Este link é sensível e expira em 1 hora.<br>Se você não solicitou, por favor ignore este e-mail.</p>
        
        <div style="margin-top: 40px;">
            <p style="font-size: 9px; color: #cbd5e1; font-weight: bold; letter-spacing: 1px;">© 2026 ASYNCX SECURITY | CYBER INTELLIGENCE</p>
        </div>
    </div>
`;

oracledb.thin = true;
oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT; 

async function validarToken(request, reply) {
    try {
        const authHeader = request.headers.authorization;
        if (!authHeader) throw new Error("Acesso negado.");
        
        const token = authHeader.split(' ')[1]; // Remove o "Bearer "
        const decoded = jwt.verify(token, JWT_SECRET);
        request.user = decoded; // Salva os dados do usuário na requisição
    } catch (err) {
        return reply.status(401).send({ success: false, message: "Sessão inválida ou expirada." });
    }
}

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
// ROTA 3: LOGIN DEFINITIVO (COM MFA, BCRYPT E JWT)
// ==========================================
fastify.post('/api/login', async (request, reply) => {
    const { email, senha, mfaToken } = request.body;
    let connection;

    try {
        connection = await getDbConnection();
        
        // 1. Busca os dados necessários para validação e para o Token
        const sql = `SELECT USER_ID, NOME_EXIBICAO, SENHA_HASH, MFA_SECRET, STATUS_MONITORAMENTO, QTD_DISPOSITIVOS 
                     FROM ASYNCX_USERS 
                     WHERE EMAIL_LOGIN = :email`;
        const result = await connection.execute(sql, { email });

        // Defesa contra enumeração: Erro genérico se não encontrar e-mail
        if (result.rows.length === 0) {
            return reply.status(401).send({ success: false, message: "Credenciais inválidas." });
        }
        
        const user = result.rows[0];

        // 2. Validação da Senha (Bcrypt)
        const senhaValida = await bcrypt.compare(senha, user.SENHA_HASH);
        if (!senhaValida) {
            return reply.status(401).send({ success: false, message: "Credenciais inválidas." });
        }

        // 3. Validação do MFA (Speakeasy)
        const verified = speakeasy.totp.verify({
            secret: user.MFA_SECRET,
            encoding: 'base32',
            token: mfaToken,
            window: 1 
        });

        if (!verified) {
            return reply.status(401).send({ success: false, message: "Código MFA inválido." });
        }

        // 4. GERAÇÃO DO TOKEN JWT (O Crachá de Acesso)
        // Guardamos o e-mail e o ID dentro do token criptografado
        const token = jwt.sign(
            { 
                userId: user.USER_ID, 
                email: email, 
                nome: user.NOME_EXIBICAO 
            }, 
            JWT_SECRET, 
            { expiresIn: '2h' } // Sessão expira automaticamente em 2 horas
        );

        // 5. Retorno de Sucesso com o Token
        return {
            success: true,
            token: token, // O frontend DEVE salvar este token
            data: {
                nome: user.NOME_EXIBICAO,
                status: user.STATUS_MONITORAMENTO,
                dispositivos: user.QTD_DISPOSITIVOS,
                servico: "Segurança Gerenciada ASYNCX"
            }
        };

    } catch (err) {
        console.error("Erro no Login:", err);
        return reply.status(500).send({ success: false, message: "Erro interno na autenticação" });
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

// ROTA PROTEGIDA: Não usa mais :email na URL
fastify.get('/api/user/dashboard-data', { preHandler: [validarToken] }, async (request, reply) => {
    // O e-mail agora vem do TOKEN decodificado pelo validarToken
    const email = request.user.email; 
    let connection;

    try {
        connection = await getDbConnection();

        // 1. Busca Perfil Detalhado
        const userSql = `SELECT USER_ID, NOME_EXIBICAO, EMAIL_LOGIN, DOCUMENTO_IDENTIDADE, 
                         ENDERECO_COMPLETO, STATUS_MONITORAMENTO, QTD_DISPOSITIVOS, 
                         ASAAS_CUSTOMER_ID, ASAAS_SUBSCRIPTION_ID 
                         FROM ASYNCX_USERS WHERE EMAIL_LOGIN = :email`;
        const userRes = await connection.execute(userSql, { email });
        
        if (userRes.rows.length === 0) return reply.status(404).send({ success: false, message: "Perfil não encontrado." });
        const user = userRes.rows[0];

        // 2. Busca Documentos
        const docsSql = `SELECT NOME_EXIBICAO, URL_PDF, TIPO_DOC, DATA_UPLOAD 
                         FROM ASYNCX_DOCUMENTS WHERE USER_ID = :id ORDER BY DATA_UPLOAD DESC`;
        const docsRes = await connection.execute(docsSql, { id: user.USER_ID });

        // 3. Busca Financeiro
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
// ROTA: ALTERAR SENHA (PROTEGIDA E COM BCRYPT)
// ==========================================

fastify.post('/api/user/change-password', { preHandler: [validarToken] }, async (request, reply) => {
    // Agora esperamos também o mfaToken do frontend
    const email = request.user.email; 
    const { novaSenha, mfaToken } = request.body; 
    
    let connection;
    try {
        if (!novaSenha || novaSenha.length < 8 || !mfaToken) {
            return reply.status(400).send({ success: false, message: "Dados incompletos ou senha fraca." });
        }

        connection = await getDbConnection();

        // 1. BUSCAR O MFA_SECRET para validar o segundo fator
        const userRes = await connection.execute(
            `SELECT MFA_SECRET FROM ASYNCX_USERS WHERE EMAIL_LOGIN = :email`,
            { email }
        );
        const user = userRes.rows[0];

        // 2. VALIDAR MFA antes de qualquer alteração
        const verified = speakeasy.totp.verify({
            secret: user.MFA_SECRET,
            encoding: 'base32',
            token: mfaToken
        });

        if (!verified) {
            return reply.status(401).send({ success: false, message: "Código MFA inválido. Operação bloqueada." });
        }

        // 3. SE OK, GERA O HASH E ATUALIZA
        const novaSenhaHasheada = await bcrypt.hash(novaSenha, 10);
        const result = await connection.execute(
            `UPDATE ASYNCX_USERS SET SENHA_HASH = :senha WHERE EMAIL_LOGIN = :email`,
            { senha: novaSenhaHasheada, email },
            { autoCommit: true }
        );

        return { success: true, message: "Senha alterada com sucesso!" };

    } catch (err) {
        console.error("Erro Crítico:", err.message);
        return reply.status(500).send({ success: false, message: "Erro ao processar alteração." });
    } finally {
        if (connection) await connection.close();
    }
});

fastify.post('/api/auth/forgot-password', async (request, reply) => {
    const { email } = request.body;
    let connection;

    try {
        connection = await getDbConnection();
        const res = await connection.execute(
            `SELECT USER_ID, NOME_EXIBICAO FROM ASYNCX_USERS WHERE EMAIL_LOGIN = :email`,
            { email }
        );

        if (res.rows.length === 0) {
            return { success: true, message: "Protocolo iniciado. Verifique seu e-mail." };
        }

        const user = res.rows[0];
        const token = crypto.randomBytes(32).toString('hex');
        const expiration = new Date();
        expiration.setHours(expiration.getHours() + 1);

        await connection.execute(
            `UPDATE ASYNCX_USERS SET RESET_TOKEN = :token, RESET_EXPIRATION = :exp WHERE EMAIL_LOGIN = :email`,
            { token, exp: expiration, email },
            { autoCommit: true }
        );

        // Resposta imediata para o site
        reply.send({ success: true, message: "Link de segurança enviado!" });

        // ENVIO VIA API RESEND (Não usa porta SMTP, por isso não dá timeout)
        const resetLink = `https://asyncx.com.br/restrito.html?setup=${token}`;
        
        await resend.emails.send({
            from: 'Segurança ASYNCX <contato@asyncx.com.br>', // REMETENTE OFICIAL
            to: email,
            subject: 'PROTOCOLO DE RECUPERAÇÃO - ASYNCX',
            html: templateEmail(
                user.NOME_EXIBICAO, 
                resetLink, 
                "SECURITY PROTOCOL", 
                "Uma solicitação de redefinição de acesso foi detectada. Se não foi você, ignore este alerta.", 
                "REDEFINIR ACESSO"
            )
        });
        
        console.log(`[RESEND OK] E-mail enviado para: ${email}`);

    } catch (err) {
        console.error("Erro Crítico:", err.message);
        return reply.status(500).send({ success: false, message: "Erro interno no servidor." });
    } finally {
        if (connection) await connection.close();
    }
});

start();