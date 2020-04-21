import os
import stat
import random
import networkx as nx
import matplotlib.pyplot as plt

BASE_P2P_PORT = 7000
BASE_API_PORT = 8000
SLEEP_TIME = 1 # second

NODE_CNT = 30
DEGREE = 5

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

    filename = 'kill_server.sh'
    kill_server_script = generate_kill_server_script(G)
    with open(filename, 'w') as f:
        f.write(kill_server_script)
    add_exec_perm(filename)

    filename = 'network.txt'
    network_description = generate_network_description(G)
    with open(filename, 'w') as f:
        f.write(network_description)
    # TODO: generate supernode script