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

// ROTA DE CONTATO (MANTIDA)
fastify.post('/api/contato', async (request, reply) => {
  const { nome, email, mensagem } = request.body;
  let connection;

  try {
    connection = await getDbConnection();

    const sql = `
      MERGE INTO LEADS_SITE t
      USING (SELECT :email AS email FROM dual) s
      ON (t.EMAIL = s.email)
      WHEN MATCHED THEN
        UPDATE SET t.NOME = :nome, t.MENSAGEM = :mensagem, t.DATA_ENVIO = CURRENT_TIMESTAMP
      WHEN NOT MATCHED THEN
        INSERT (NOME, EMAIL, MENSAGEM, DATA_ENVIO)
        VALUES (:nome, :email, :mensagem, CURRENT_TIMESTAMP)`;
    
    await connection.execute(sql, { nome, email, mensagem }, { autoCommit: true });

    if (process.env.TELEGRAM_TOKEN && process.env.TELEGRAM_CHAT_ID) {
      const telegramUrl = `https://api.telegram.org/bot${process.env.TELEGRAM_TOKEN}/sendMessage`;
      const textoTelegram = `🚀 *NOVO LEAD ASYNCX*\n\n*Nome:* ${nome}\n*E-mail:* ${email}\n*Mensagem:* ${mensagem}`;
      
      fetch(telegramUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: process.env.TELEGRAM_CHAT_ID,
          text: textoTelegram,
          parse_mode: 'Markdown'
        })
      }).catch(e => console.error("Falha no Telegram:", e.message));
    }
    
    return { 
      success: true, 
      message: 'Protocolo ASYNCX processado! Seus dados foram salvos ou atualizados com sucesso.' 
    };

  } catch (err) {
    return reply.status(500).send({ success: false, message: "Erro no Oracle Cloud", oraCode: err.code });
  } finally {
    if (connection) await connection.close();
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