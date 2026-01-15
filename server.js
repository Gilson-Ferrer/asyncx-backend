require('dotenv').config();
const fastify = require('fastify')({ logger: false });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');

oracledb.thin = true;

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
    const sql = `INSERT INTO LEADS_SITE (NOME, EMAIL, MENSAGEM) VALUES (:nome, :email, :mensagem)`;
    
    await connection.execute(sql, { nome, email, mensagem }, { autoCommit: true });
    
    return { 
      success: true, 
      message: 'Protocolo ASYNCX registrado! Sua mensagem foi enviada com sucesso.' 
    };

  } catch (err) {
    return reply.status(500).send({ 
      success: false, 
      message: "Erro ao processar solicitação.",
      oraCode: err.code 
    });
  } finally {
    if (connection) {
      try { await connection.close(); } catch (e) { /* silent close */ }
    }
  }
});

fastify.get('/', async () => {
  return { status: 'online', service: 'ASYNCX-API', mode: 'TLS-Direct' };
});

const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 10000, host: '0.0.0.0' });
  } catch (err) {
    process.exit(1);
  }
};
start();