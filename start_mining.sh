GAP=1400000
curl http://127.0.0.1:7000/miner/start?lambda=$GAP
sleep .2
curl http://127.0.0.1:7001/miner/start?lambda=$GAP
sleep .2
curl http://127.0.0.1:7002/miner/start?lambda=$GAP