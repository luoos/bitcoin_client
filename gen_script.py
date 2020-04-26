import os
import stat
import random
import networkx as nx
import matplotlib.pyplot as plt

BASE_P2P_PORT = 7000
BASE_API_PORT = 8000
SLEEP_TIME = 1 # second
MINING_LAMBDA = 1400000

SUPERNODE_P2P_PORT = 9000
SUPERNODE_API_PORT = 9090
SUPERNODE_PROBE = 1

NODE_CNT = 50
DEGREE = 8

def generate_start_server_script(G):
    started_node = set()
    script = ['cargo build --release\n']
    for n in G.nodes():
        script.append(f'cargo run --release -- -vv --p2p 127.0.0.1:{n+BASE_P2P_PORT} ')
        script.append(f'--api 127.0.0.1:{n+BASE_API_PORT} ')
        for neighbor in G[n]:
            if neighbor in started_node:
                script.append(f'-c 127.0.0.1:{neighbor+BASE_P2P_PORT} ')
        script.append('&\n')
        script.append(f'sleep {SLEEP_TIME}\n')
        started_node.add(n)
    script.pop() # pop the last sleep command
    return ''.join(script)

def generate_start_mining_script(G):
    script = [f'GAP={MINING_LAMBDA}\n']
    for n in G.nodes():
        script.append(f'curl http://127.0.0.1:{n+BASE_API_PORT}/miner/start?lambda=$GAP\n')
        script.append('sleep .2\n')
    return ''.join(script)

def generate_kill_server_script(G):
    script = []
    for n in G.nodes():
        script.append(f'kill $(lsof -t -i:{n+BASE_API_PORT})\n')
    return ''.join(script)

def generate_network_description(G):
    content = []
    for n in G.nodes():
        line = [f'{n+BASE_P2P_PORT}:']
        for neighbor in G[n]:
            line.append(f'{neighbor+BASE_P2P_PORT},')
        line = ''.join(line).strip(',')
        content.append(line)
        content.append('\n')
    content.pop()
    return ''.join(content)

def generate_supernode_script(G, p2p_port, api_port, probe_cnt):
    script = [f'cargo run --release -- -vv --supernode -p {probe_cnt} ']
    script.append(f'--p2p 127.0.0.1:{p2p_port} ')
    script.append(f'--api 127.0.0.1:{api_port} ')
    for n in G.nodes():
        script.append(f'-c 127.0.0.1:{BASE_P2P_PORT+n} ')
    script.append('&')
    return ''.join(script)

def generate_kill_supernode_script(api_port):
    script = f'kill $(lsof -t -i:{api_port})'
    return script

def add_exec_perm(filename):
    st = os.stat(filename)
    os.chmod(filename, st.st_mode | stat.S_IEXEC)

if __name__ == '__main__':
    G = nx.random_regular_graph(DEGREE, NODE_CNT)
    nx.draw(G, pos=nx.circular_layout(G), node_color='r', edge_color='b', with_labels=True)
    plt.savefig('network.jpg')

    filename = 'run_server.sh'
    regular_server_script = generate_start_server_script(G)
    with open(filename, 'w') as f:
        f.write(regular_server_script)
    add_exec_perm(filename)

    filename = 'run_mining.sh'
    run_mining_script = generate_start_mining_script(G)
    with open(filename, 'w') as f:
        f.write(run_mining_script)
    add_exec_perm(filename)

    filename = 'kill_server.sh'
    kill_server_script = generate_kill_server_script(G)
    with open(filename, 'w') as f:
        f.write(kill_server_script)
    add_exec_perm(filename)

    filename = 'network.txt'
    network_description = generate_network_description(G)
    with open(filename, 'w') as f:
        f.write(network_description)

    filename = 'run_supernode.sh'
    supernode_script = generate_supernode_script(G,
            SUPERNODE_P2P_PORT, SUPERNODE_API_PORT, SUPERNODE_PROBE)
    with open(filename, 'w') as f:
        f.write(supernode_script)
    add_exec_perm(filename)

    filename = 'kill_supernode.sh'
    kill_supernode_script = generate_kill_supernode_script(SUPERNODE_API_PORT)
    with open(filename, 'w') as f:
        f.write(kill_supernode_script)
    add_exec_perm(filename)