require('dotenv').config();
const fastify = require('fastify')({ logger: false });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');
const rateLimit = require('@fastify/rate-limit');

oracledb.thin = true;

fastify.register(rateLimit, {
  max: 1,
  timeWindow: '5 minutes',
  errorResponseBuilder: () => ({
    success: false,
    message: '⚠️ Limite de segurança: Você só pode atualizar sua mensagem a cada 5 minutos.'
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