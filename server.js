require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');

// Forçar o Modo Thin explicitamente (100% JavaScript)
oracledb.thin = true;

fastify.register(cors, { 
  origin: ["https://gilson-ferrer.github.io", "https://www.asyncx.com.br", "https://asyncx.com.br"],
  methods: ["POST", "GET"]
});

// Conexão Simplificada via TLS (Sem Wallet) com Debug
async function getDbConnection() {
  return await oracledb.getConnection({
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    connectionString: process.env.DB_CONNECTION_STRING.trim()
  });
}

// ROTA: Salvar Lead
fastify.post('/api/contato', async (request, reply) => {
  const { nome, email, mensagem } = request.body;
  let connection;

  try {
    connection = await getDbConnection();
    const sql = `INSERT INTO LEADS_SITE (NOME, EMAIL, MENSAGEM) VALUES (:nome, :email, :mensagem)`;
    
    // Usando bind por objeto para garantir compatibilidade
    await connection.execute(sql, { nome, email, mensagem }, { autoCommit: true });
    
    fastify.log.info(`✅ Lead salvo via TLS: ${email}`);
    return { success: true, message: 'Protocolo ASYNCX registrado com sucesso.' };

  } catch (err) {
    fastify.log.error("❌ Erro no Banco:", err.message);
    return reply.status(500).send({ 
      success: false, 
      message: "Falha na comunicação com o Oracle Cloud",
      details: err.message,
      code: err.code 
    });
  } finally {
    if (connection) {
      try { 
        await connection.close(); 
        console.log("LOG ASYNCX: Conexão fechada.");
      } catch (e) { 
        console.error("Erro ao fechar:", e); 
      }
    }
  }
});

// Health Check
fastify.get('/', async () => {
  return { status: 'online', mode: 'Oracle TLS (No-Wallet)', timestamp: new Date().toISOString() };
});

const start = async () => {
  try {
    const port = process.env.PORT || 10000;
    await fastify.listen({ port: port, host: '0.0.0.0' });
    console.log(`🚀 Backend ASYNCX ativo na porta ${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start();