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
            <p style="font-size: 9px; color: #cbd5e1; font-weight: bold; letter-spacing: 1px;">© 2026 ASYNCX | SOLUÇÕES EM TI E SEGURANÇA DIGITAL</p>
        </div>
    </div>
`;

oracledb.thin = true;
oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT; 

async function validarToken(request, reply) {
    try {
        const authHeader = request.headers.authorization;
        if (!authHeader) throw new Error("Acesso negado.");
        
        const token = authHeader.split(' ')[1]; 
        const decoded = jwt.verify(token, JWT_SECRET);
        request.user = decoded; 
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


fastify.get('/api/auth/setup-check/:token', async (request, reply) => {
    const { token } = request.params;
    let connection;
    try {
        connection = await getDbConnection();
        const sql = `SELECT USER_ID, EMAIL_LOGIN, MFA_SECRET, NOME_EXIBICAO, RESET_EXPIRATION, MFA_SETUP_COMPLETE 
                     FROM ASYNCX_USERS WHERE RESET_TOKEN = :token`;
        const result = await connection.execute(sql, { token });

        if (result.rows.length === 0) return reply.status(400).send({ success: false, message: "Link inválido ou já utilizado." });

        const user = result.rows[0];
        const agora = new Date();
        const expiracao = new Date(user.RESET_EXPIRATION);

        if (agora > expiracao) return reply.status(400).send({ success: false, message: "Link expirado." });

        let qrCodeDataURL = null;

        if (user.MFA_SETUP_COMPLETE === 0) {
            const otpauth_url = speakeasy.otpauthURL({
                secret: user.MFA_SECRET,
                label: `ASYNCX:${user.EMAIL_LOGIN}`,
                issuer: 'ASYNCX',
                encoding: 'base32'
            });
            qrCodeDataURL = await QRCode.toDataURL(otpauth_url);
        }

        return { 
            success: true, 
            nome: user.NOME_EXIBICAO, 
            email: user.EMAIL_LOGIN,
            needsMFA: user.MFA_SETUP_COMPLETE === 0, 
            qrCode: qrCodeDataURL 
        };
    } finally {
        if (connection) await connection.close();
    }
});

fastify.post('/api/auth/setup-finalize', async (request, reply) => {
    const { token, senha } = request.body; 
    let connection;
    try {
        connection = await getDbConnection();
        const userRes = await connection.execute(
            `SELECT USER_ID, RESET_EXPIRATION FROM ASYNCX_USERS WHERE RESET_TOKEN = :token`, 
            { token }
        );
        
        if (userRes.rows.length === 0) throw new Error("Link inválido.");
        
        if (new Date() > new Date(userRes.rows[0].RESET_EXPIRATION)) {
            throw new Error("Link expirou.");
        }

        const user = userRes.rows[0];
        const senhaHasheada = await bcrypt.hash(senha, saltRounds);

        await connection.execute(
            `UPDATE ASYNCX_USERS 
             SET SENHA_HASH = :senha, 
                 MFA_SETUP_COMPLETE = 1, 
                 RESET_TOKEN = NULL, 
                 RESET_EXPIRATION = NULL, 
                 STATUS_MONITORAMENTO = 'ATIVO' 
             WHERE USER_ID = :id`,
            { senha: senhaHasheada, id: user.USER_ID },
            { autoCommit: true }
        );

        return { success: true, message: "Segurança ASYNCX atualizada!" };
    } catch (err) {
        console.error("Erro Finalize:", err.message);
        return reply.status(500).send({ success: false, message: err.message });
    } finally {
        if (connection) await connection.close();
    }
});


fastify.post('/api/login', async (request, reply) => {
    const { email, senha, mfaToken } = request.body;
    let connection;

    try {
        connection = await getDbConnection();
        
        const sql = `SELECT USER_ID, NOME_EXIBICAO, SENHA_HASH, MFA_SECRET, STATUS_MONITORAMENTO, QTD_DISPOSITIVOS 
                     FROM ASYNCX_USERS 
                     WHERE EMAIL_LOGIN = :email`;
        const result = await connection.execute(sql, { email });

        if (result.rows.length === 0) {
            return reply.status(401).send({ success: false, message: "Credenciais inválidas." });
        }
        
        const user = result.rows[0];

        const senhaValida = await bcrypt.compare(senha, user.SENHA_HASH);
        if (!senhaValida) {
            return reply.status(401).send({ success: false, message: "Credenciais inválidas." });
        }

        const verified = speakeasy.totp.verify({
            secret: user.MFA_SECRET,
            encoding: 'base32',
            token: mfaToken,
            window: 1 
        });

        if (!verified) {
            return reply.status(401).send({ success: false, message: "Código MFA inválido." });
        }

        const token = jwt.sign(
            { 
                userId: user.USER_ID, 
                email: email, 
                nome: user.NOME_EXIBICAO 
            }, 
            JWT_SECRET, 
            { expiresIn: '2h' } 
        );

        return {
            success: true,
            token: token, 
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


fastify.post('/api/telegram-notify', async (request, reply) => {
    const { nome, email, mensagem } = request.body;
    const token = process.env.TELEGRAM_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    if (!token || !chatId) return reply.status(500).send({ success: false, message: "Erro de configuração." });

    try {
        const telegramUrl = `https://api.telegram.org/bot${token}/sendMessage`;
        const textoTelegram = `*NOVO CONTATO ASYNCX*\n\n*Nome:* ${nome}\n*E-mail:* ${email}\n*Mensagem:* ${mensagem}`;

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


fastify.get('/api/user/dashboard-data', { preHandler: [validarToken] }, async (request, reply) => {

    const email = request.user.email; 
    let connection;

    try {
        connection = await getDbConnection();

        const userSql = `SELECT USER_ID, NOME_EXIBICAO, EMAIL_LOGIN, DOCUMENTO_IDENTIDADE, 
                        ENDERECO_COMPLETO, STATUS_MONITORAMENTO, QTD_DISPOSITIVOS, 
                        ASAAS_CUSTOMER_ID, ASAAS_SUBSCRIPTION_ID, TIPO_SERVICO 
                        FROM ASYNCX_USERS WHERE EMAIL_LOGIN = :email`;
        const userRes = await connection.execute(
            userSql, 
            { email }, 
            { outFormat: oracledb.OUT_FORMAT_OBJECT } 
        );
        
        if (userRes.rows.length === 0) return reply.status(404).send({ success: false, message: "Perfil não encontrado." });
        const user = userRes.rows[0];


        const docsSql = `SELECT NOME_EXIBICAO, URL_PDF, TIPO_DOC, DATA_UPLOAD 
                         FROM ASYNCX_DOCUMENTS WHERE USER_ID = :id ORDER BY DATA_UPLOAD DESC`;
        const docsRes = await connection.execute(docsSql, { id: user.USER_ID });

        const billsSql = `SELECT ASAAS_PAYMENT_ID, 
                                VALOR, 
                                STATUS_PAGO, 
                                LINK_BOLETO, 
                                TO_CHAR(DATA_VENCIMENTO, 'DD/MM/YYYY') as DATA_VENCIMENTO, -- Mudamos o alias aqui
                                DESCRICAO
                        FROM ASYNCX_BILLING 
                        WHERE USER_ID = :id 
                        ORDER BY DATA_VENCIMENTO DESC 
                        FETCH FIRST 12 ROWS ONLY`;
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

        const userRes = await connection.execute(
            `SELECT MFA_SECRET FROM ASYNCX_USERS WHERE EMAIL_LOGIN = :email`,
            { email }
        );
        const user = userRes.rows[0];

        const verified = speakeasy.totp.verify({
            secret: user.MFA_SECRET,
            encoding: 'base32',
            token: mfaToken
        });

        if (!verified) {
            return reply.status(401).send({ success: false, message: "Código MFA inválido. Operação bloqueada." });
        }

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
            return { success: true, message: "Protocolo iniciado. Verifique seu e-mail se estiver cadastrado." };
        }

        const user = res.rows[0];
        const token = crypto.randomBytes(32).toString('hex');
        const expiration = new Date(Date.now() + 3600 * 1000); 

        await connection.execute(
            `UPDATE ASYNCX_USERS 
             SET RESET_TOKEN = :token, RESET_EXPIRATION = :exp 
             WHERE EMAIL_LOGIN = :email`,
            { token, exp: expiration, email },
            { autoCommit: true }
        );

        reply.send({ success: true, message: "Link de segurança enviado!" });

        const resetLink = `https://asyncx.com.br/restrito.html?setup=${token}`;
        
        resend.emails.send({
            from: 'Segurança ASYNCX <contato@asyncx.com.br>',
            to: email,
            subject: 'PROTOCOLO DE RECUPERAÇÃO - ASYNCX',
            html: templateEmail(
                user.NOME_EXIBICAO, 
                resetLink, 
                "SECURITY PROTOCOL", 
                "Uma solicitação de redefinição de acesso foi detectada para sua conta. Este link expira em 1 hora.", 
                "REDEFINIR ACESSO AGORA"
            )
        }).then(() => {
            console.log(`[RESEND OK] E-mail enviado com sucesso para: ${email}`);
        }).catch(err => {
            console.error(`[RESEND ERROR]: Falha no envio para ${email}:`, err.message);
        });

    } catch (err) {
        console.error("Erro Crítico no Forgot Password:", err.message);

        if (!reply.sent) {
            return reply.status(500).send({ success: false, message: "Erro interno no servidor." });
        }
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (closeErr) {
                console.error("Erro ao fechar conexão Oracle:", closeErr.message);
            }
        }
    }
});

fastify.post('/api/auth/complete-reset', async (request, reply) => {
    const { token, password } = request.body; 
    let connection;
    try {
        connection = await getDbConnection();
        
        const check = await connection.execute(
            `SELECT USER_ID, RESET_EXPIRATION FROM ASYNCX_USERS WHERE RESET_TOKEN = :token`,
            { token }
        );

        if (check.rows.length === 0) {
            return reply.status(400).send({ success: false, message: "Link inválido." });
        }

        const expiracao = new Date(check.rows[0].RESET_EXPIRATION);
        if (new Date() > expiracao) {
            return reply.status(400).send({ success: false, message: "Link expirado." });
        }

        const hash = await bcrypt.hash(password, 10);

        const sql = `UPDATE ASYNCX_USERS 
                     SET SENHA_HASH = :hash, 
                         RESET_TOKEN = NULL, 
                         RESET_EXPIRATION = NULL,
                         MFA_SETUP_COMPLETE = 1
                     WHERE RESET_TOKEN = :token`;

        await connection.execute(sql, { hash, token }, { autoCommit: true });
        return { success: true, message: "Senha atualizada com sucesso!" };
    } catch (err) {
        console.error("Erro no Reset:", err.message);
        return reply.status(500).send({ success: false, message: "Erro interno." });
    } finally {
        if (connection) await connection.close();
    }
});


fastify.post('/api/webhooks/asaas', async (request, reply) => {
    const { event, payment } = request.body;
    let connection;

    console.log(`[WEBHOOK ASAAS] Evento: ${event} | ID: ${payment.id} | Sub: ${payment.subscription || 'N/A'}`);

    try {
        connection = await getDbConnection();

        if (event === 'PAYMENT_CREATED' && payment.subscription) {
            const sqlInsert = `INSERT INTO ASYNCX_BILLING 
                (USER_ID, ASAAS_PAYMENT_ID, VALOR, DATA_VENCIMENTO, STATUS_PAGO, LINK_BOLETO, DESCRICAO)
                SELECT USER_ID, :payId, :val, :venc, 'PENDENTE', :link, :desc
                FROM ASYNCX_USERS WHERE ASAAS_CUSTOMER_ID = :cusId
                FETCH FIRST 1 ROW ONLY`;

            const resInsert = await connection.execute(sqlInsert, {
                payId: payment.id,
                val: payment.value,
                venc: new Date(payment.dueDate),
                link: payment.invoiceUrl || payment.bankSlipUrl,
                desc: payment.description || 'Assinatura Mensal ASYNCX',
                cusId: payment.customer
            }, { autoCommit: true });

            if (resInsert.rowsAffected > 0) {
                console.log(`[ORACLE] Próxima fatura ${payment.id} inserida automaticamente.`);
            }
        }

        const eventosSucesso = ['PAYMENT_CONFIRMED', 'PAYMENT_RECEIVED', 'PAYMENT_RECEIVED_IN_CASH_UNDONE'];
        
        if (eventosSucesso.includes(event)) {
            const payId = payment.id ? payment.id.trim() : null;
            const subId = payment.subscription ? payment.subscription.trim() : null;
            const sqlUpdate = `UPDATE ASYNCX_BILLING 
                               SET STATUS_PAGO = 'PAGO' 
                               WHERE TRIM(ASAAS_PAYMENT_ID) = :id1 
                                  OR TRIM(ASAAS_PAYMENT_ID) = :id2`;

            const result = await connection.execute(
                sqlUpdate, 
                { id1: payId, id2: subId }, 
                { autoCommit: true }
            );

            console.log(`[ORACLE] Status PAGO: ${result.rowsAffected} linha(s) atualizada(s).`);
        }

        return reply.status(200).send({ success: true });

    } catch (err) {
        console.error("[ERRO WEBHOOK]", err.message);
        return reply.status(200).send({ error: err.message });
    } finally {
        if (connection) await connection.close();
    }
});

start();