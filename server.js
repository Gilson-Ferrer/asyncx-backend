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
  try {
    console.log("LOG ASYNCX: Tentando conectar via TLS...");
    return await oracledb.getConnection({
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      connectionString: process.env.DB_CONNECTION_STRING.trim()
    });
  } catch (err) {
    // Imprime o erro técnico detalhado no console do Render
    console.error("ERRO CRÍTICO NA CONEXÃO ORACLE:", err);
    throw err; // Repassa o erro para a rota tratar
  }
}

// ROTA ATUALIZADA COM TRATAMENTO DE ERRO EXPOSTO
fastify.post('/api/contato', async (request, reply) => {
  const { nome, email, mensagem } = request.body;
  let connection;

  try {
    connection = await getDbConnection();
    const sql = `INSERT INTO LEADS_SITE (NOME, EMAIL, MENSAGEM) VALUES (:nome, :email, :mensagem)`;
    await connection.execute(sql, { nome, email, mensagem }, { autoCommit: true });
    
    return { success: true, message: 'Solicitação registrada com sucesso.' };

  } catch (err) {
    // IMPORTANTE: Agora o erro vai aparecer no seu 'alert' do navegador
    return reply.status(500).send({ 
      success: false, 
      message: "Erro no Banco de Dados",
      oraCode: err.code,      // Ex: ORA-12170
      details: err.message    // Mensagem completa do erro
    });
  } finally {
    if (connection) {
      try { await connection.close(); } catch (e) { console.error("Erro ao fechar:", e); }
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