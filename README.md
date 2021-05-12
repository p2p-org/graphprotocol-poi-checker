# graphprotocol-poi-checker
Python3 script to check POI across multi indexers for defined subgraph.

## Usage example:

**Never share POI for open allocations!!!!!!**

```bash
$ python3 check_poi.py --help

python3 check_poi.py --help
usage: check_poi.py [-h] --subgraph_ipfs_hash SUBGRAPH_IPFS_HASH [--graph_endpoint GRAPH_ENDPOINT] [--local_index_node_endpoint LOCAL_INDEX_NODE_ENDPOINT]
                    [--block_hash_endpoint BLOCK_HASH_ENDPOINT] [--number_allocation_to_check NUMBER_ALLOCATION_TO_CHECK]

optional arguments:
  -h, --help            show this help message and exit
  --subgraph_ipfs_hash SUBGRAPH_IPFS_HASH
                        subgraph ipfs_hash to analyze
  --graph_endpoint GRAPH_ENDPOINT
                        graph network endpoint (default: https://gateway.network.thegraph.com/network)
  --local_index_node_endpoint LOCAL_INDEX_NODE_ENDPOINT
                        local index node endpoint (default: http://graph-index-node:8030/graphql)
  --block_hash_endpoint BLOCK_HASH_ENDPOINT
                        ethereum endpoint to request block hash (default: https://eth-mainnet.alchemyapi.io/v2/demo)
  --number_allocation_to_check NUMBER_ALLOCATION_TO_CHECK
                        number of last closed allocation to check poi (default: 10)
```

## Requirements:

```pip3 install -r requirements.txt```
