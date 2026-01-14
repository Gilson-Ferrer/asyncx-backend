require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors'); // Verifique se tem o @

fastify.register(cors, { 
  origin: "*" // Por enquanto deixe asterisco para testarmos, depois restringimos ao seu domínio
});

// ROTA 1: Verificação de Darkweb (Pwned API)
fastify.post('/api/check-pwned', async (request, reply) => {
  const { email } = request.body;
  
  try {
    // Chamada para a API Have I Been Pwned
    // Nota: Requer uma API Key paga deles ($3.50/mês) ou usaremos um mock por enquanto
    const response = await axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${email}`, {
      headers: { 'hibp-api-key': process.env.PWNED_API_KEY }
    });
    
    return { status: 'vazado', data: response.data };
  } catch (error) {
    if (error.response && error.response.status === 404) {
      return { status: 'seguro', message: 'Nenhum vazamento encontrado.' };
    }
    return { status: 'erro', message: 'Erro ao consultar base de dados.' };
  }
});

// ROTA 2: Receber Lead do Formulário de Contato e salvar no Oracle
fastify.post('/api/contato', async (request, reply) => {
  const { nome, email, mensagem } = request.body;
  
  // Aqui no futuro entra a lógica:
  // 1. Conectar no Oracle
  // 2. INSERT INTO leads (nome, email, mensagem) VALUES (...)
  
  console.log(`Novo Lead recebido: ${nome} - ${email}`);
  return { success: true, message: 'Solicitação enviada com sucesso!' };
});

// Iniciar Servidor
const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start();