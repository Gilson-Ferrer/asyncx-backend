require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');

// Configuração de CORS para o GitHub Pages
fastify.register(cors, { 
  origin: ["https://gilson-ferrer.github.io", "https://www.asyncx.com.br", "https://asyncx.com.br"],
  methods: ["POST", "GET"]
});

// Conexão Simplificada via TLS (Sem Wallet)
async function getDbConnection() {
  return await oracledb.getConnection({
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    connectionString: process.env.DB_CONNECTION_STRING
  });
}

// ROTA: Salvar Lead
fastify.post('/api/contato', async (request, reply) => {
  const { nome, email, mensagem } = request.body;
  let connection;

  try {
    connection = await getDbConnection();
    const sql = `INSERT INTO LEADS_SITE (NOME, EMAIL, MENSAGEM) VALUES (:nome, :email, :mensagem)`;
    await connection.execute(sql, { nome, email, mensagem }, { autoCommit: true });
    
    fastify.log.info(`✅ Lead salvo via TLS: ${email}`);
    return { success: true, message: 'Protocolo ASYNCX registrado com sucesso.' };

  } catch (err) {
    fastify.log.error("❌ Erro no Banco:", err.message);
    return reply.status(500).send({ success: false, details: err.message });
  } finally {
    if (connection) {
      try { await connection.close(); } catch (e) { console.error(e); }
    }
  }
});

// Health Check
fastify.get('/', async () => {
  return { status: 'online', mode: 'Oracle TLS (No-Wallet)' };
});

const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 10000, host: '0.0.0.0' });
    console.log("🚀 Backend ASYNCX em Modo TLS Direto.");
  } catch (err) {
    process.exit(1);
  }
};
start();