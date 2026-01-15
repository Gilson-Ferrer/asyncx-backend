require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');

// Configuração do Driver Oracle para ler a Wallet no Render
try {
  oracledb.initOracleClient({ configDir: process.env.TNS_ADMIN || '/etc/secrets' });
} catch (err) {
  console.error("Erro ao inicializar Oracle Client:", err);
}

fastify.register(cors, { origin: "*" });

// Função para obter conexão com o Oracle
async function getDbConnection() {
  return await oracledb.getConnection({
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    connectionString: process.env.DB_CONNECTION_STRING // Ex: asyncxdb_tp
  });
}

// ROTA: Receber Lead e SALVAR no Oracle
fastify.post('/api/contato', async (request, reply) => {
  const { nome, email, mensagem } = request.body;
  let connection;

  try {
    connection = await getDbConnection();
    
    const sql = `INSERT INTO LEADS_SITE (NOME, EMAIL, MENSAGEM) VALUES (:nome, :email, :mensagem)`;
    const binds = { nome, email, mensagem };
    
    await connection.execute(sql, binds, { autoCommit: true });
    
    console.log(`✅ Lead salvo no Oracle: ${email}`);
    return { success: true, message: 'Solicitação registrada no protocolo ASYNCX.' };

  } catch (err) {
    fastify.log.error(err);
    return reply.status(500).send({ success: false, message: 'Erro interno no servidor de dados.' });
  } finally {
    if (connection) {
      try { await connection.close(); } catch (e) { console.error(e); }
    }
  }
});

// Iniciar Servidor
const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 10000, host: '0.0.0.0' });
    console.log("🚀 Servidor ASYNCX ativo e aguardando requisições.");
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start();