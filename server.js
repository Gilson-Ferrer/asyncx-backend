require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');

/**
 * CONFIGURAÇÃO DO MODO THIN (MODO LEVE)
 * No Render, não chamamos 'initOracleClient'. 
 * O driver entra em modo Thin automaticamente, facilitando a conexão mTLS.
 */

// Registrar CORS para permitir que o seu site no GitHub Pages acesse a API
fastify.register(cors, { 
  origin: ["https://gilson-ferrer.github.io", "https://www.asyncx.com.br", "https://asyncx.com.br"],
  methods: ["POST", "GET"]
});

/**
 * FUNÇÃO DE CONEXÃO COM ORACLE CLOUD
 */
async function getDbConnection() {
  return await oracledb.getConnection({
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    connectionString: process.env.DB_CONNECTION_STRING,
    // Mudança estratégica: 
    // No Render, aponte o TNS_ADMIN explicitamente aqui também
    configDir: '/etc/secrets', 
    walletLocation: '/etc/secrets',
    walletPassword: process.env.WALLET_PASS
  });
}

/**
 * ROTA: RECEBER LEAD E SALVAR NO BANCO
 */
fastify.post('/api/contato', async (request, reply) => {
  const { nome, email, mensagem } = request.body;
  let connection;

  try {
    // Abrir conexão
    connection = await getDbConnection();
    
    // Comando SQL para inserir o lead
    const sql = `INSERT INTO LEADS_SITE (NOME, EMAIL, MENSAGEM) VALUES (:nome, :email, :mensagem)`;
    const binds = { nome, email, mensagem };
    
    // Executar com commit automático
    await connection.execute(sql, binds, { autoCommit: true });
    
    fastify.log.info(`✅ Lead salvo no Oracle com sucesso: ${email}`);
    
    return { 
      success: true, 
      message: 'Solicitação registrada no protocolo ASYNCX com sucesso.' 
    };

  } catch (err) {
    fastify.log.error("❌ Erro na operação do banco:", err.message);
    
    // Retornar erro 500 com a mensagem técnica para diagnóstico
    return reply.status(500).send({ 
      success: false, 
      error: 'Erro interno no banco de dados',
      details: err.message 
    });
  } finally {
    // SEMPRE fechar a conexão no bloco finally para evitar vazamento de memória
    if (connection) {
      try {
        await connection.close();
      } catch (e) {
        fastify.log.error("Erro ao fechar conexão:", e);
      }
    }
  }
});

/**
 * ROTA DE SAÚDE (HEALTH CHECK)
 * Útil para verificar se o backend está online sem precisar enviar formulário
 */
fastify.get('/', async () => {
  return { status: 'online', service: 'ASYNCX Backend', mode: 'Oracle Thin Mode' };
});

/**
 * INICIALIZAÇÃO DO SERVIDOR
 */
const start = async () => {
  try {
    // O Render exige host 0.0.0.0 e usa a porta definida na variável PORT
    const port = process.env.PORT || 10000;
    await fastify.listen({ port: port, host: '0.0.0.0' });
    console.log(`
    🚀 ==========================================
    🚀 ASYNCX BACKEND ESTÁ ONLINE
    🚀 PORTA: ${port}
    🚀 MODO: Oracle Database Cloud (Thin)
    🚀 ==========================================
    `);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();