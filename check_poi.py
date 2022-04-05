#!/usr/bin/env python3

import base58
import argparse
import logging
import sys
import requests
import json
import os
from string import Template
import argparse

log_level="INFO" #Can be DEBUG, INFO, WARNING, ERROR, CRITICAL

# Logger Entry
logger = logging.getLogger(__name__)


def logging_func():
    logging.basicConfig(format='%(levelname)s %(asctime)s %(message)s', datefmt='%d/%m/%Y %H:%M:%S', level=log_level)


def to_id(hash):
    bytes_value = base58.b58decode(hash)
    hex_value = bytes_value.hex()
    return "0x"+hex_value[4:]


def to_ipfs_hash(id):
    #https://ethereum.stackexchange.com/questions/17094/how-to-store-ipfs-hash-using-bytes32
    hex_value = bytes.fromhex("1220"+id[2:])
    ipfs_hash = base58.b58encode(hex_value)
    return ipfs_hash.decode("utf-8")


def generate_poi(indexer_id, block_number, block_hash, subgraph_ipfs_hash):
    t = Template("""query MyQuery {
        proofOfIndexing(
          subgraph: "$subgraph_ipfs_hash",
          blockNumber: $block_number,
          blockHash: "$block_hash",
          indexer: "$indexer_id")
       }""")
    query_data = t.substitute(subgraph_ipfs_hash=subgraph_ipfs_hash,
                              block_number=block_number,
                              block_hash=block_hash,
                              indexer_id=indexer_id)
    request = requests.post(local_index_node_endpoint, json={'query': query_data})

    if request.status_code != 200:
        logger.error("error in generate_poi")
        logger.error(request.status_code)
        sys.exit(1)

    json_response = json.loads(request.text)

    if "errors" in json_response:
        logger.error("error in generate_poi")
        logger.error(json_response["errors"])
        sys.exit(1)

    return json_response["data"]["proofOfIndexing"]


def convert_tokens(amount):
    if len(amount) <= 18:
        return "~0"
    else:
        return str(amount[:-18])


def get_indexers_poi_epoch(subgraph, zero_pois):
    indexers_poi_epoch = []
    if indexers_list == '["all"]':
        t = Template("""query MyQuery {
          allocations(where: {subgraphDeployment: "$subgraph", $zero_pois status_not: Active }, first: $number_allocation_to_check, orderBy: closedAtEpoch, orderDirection: desc) {
            closedAtEpoch
            indexer {
             id
            }
            allocatedTokens
            poi
          }
        }""")
        query_data = t.substitute(subgraph=subgraph,
                                  number_allocation_to_check=number_allocation_to_check,
                                  zero_pois=zero_pois)
    else:
        t = Template("""query MyQuery {
          allocations(where: {subgraphDeployment: "$subgraph", $zero_pois status_not: Active, indexer_in: $indexers_list }, first: $number_allocation_to_check, orderBy: closedAtEpoch, orderDirection: desc) {
            closedAtEpoch
            indexer {
             id
            }
            poi
            allocatedTokens
          }
        }""")
        query_data = t.substitute(subgraph=subgraph,
                                  number_allocation_to_check=number_allocation_to_check,
                                  indexers_list=indexers_list,
                                  zero_pois=zero_pois)

    request = requests.post(graph_endpoint, json={'query': query_data})

    if request.status_code != 200:
        logger.error("error in get_indexers_poi_epoch")
        logger.error(request.text)
        sys.exit(1)

    json_response = json.loads(request.text)

    if "errors" in json_response:
        logger.error("error in get_indexers_poi_epoch")
        logger.error(json_response["errors"])
        sys.exit(1)

    for i in json_response["data"]["allocations"]:
        indexers_poi_epoch.append({"indexer_id": i["indexer"]["id"], "epoch": i["closedAtEpoch"], "poi": i["poi"], "allocatedTokens": convert_tokens(str(i["allocatedTokens"]))})

    return indexers_poi_epoch


def get_current_epoch():
    query_data = '{\n graphNetworks {\n currentEpoch \n} \n}'
    request = requests.post(graph_endpoint, json={'query': query_data})

    if request.status_code != 200:
        logger.error("error in get_current_epoch")
        logger.error(request.text)
        sys.exit(1)

    json_response = json.loads(request.text)

    if "errors" in json_response:
        logger.error("error in get_current_epoch")
        logger.error(json_response["errors"])
        sys.exit(1)

    return json_response["data"]["graphNetworks"][0]["currentEpoch"]


def get_start_block(epoch):
    t = Template('{ epoch(id: $epoch) { startBlock } }')
    query_data = t.substitute(epoch=epoch)
    request = requests.post(graph_endpoint, json={'query': query_data})

    if request.status_code != 200:
        logger.error("error in get_start_block")
        logger.error(request.text)
        sys.exit(1)

    json_response = json.loads(request.text)

    if "errors" in json_response:
        logger.error("error in get_start_block")
        logger.error(json_response["errors"])
        sys.exit(1)

    return json_response["data"]["epoch"]["startBlock"]


def get_start_block_hash(epoch_start_block):
    payload = {
        "method": "eth_getBlockByNumber",
        "params": ['{}'.format(hex(epoch_start_block)), False],
        "jsonrpc": "2.0",
        "id": 1,
    }

    response = requests.post(block_hash_endpoint, json=payload).json()

    if "error" in response:
        logger.error("error in get_start_block_hash")
        logger.error(response["error"])
        sys.exit(1)

    return response["result"]["hash"]


#Dirty hack to replace ' for "
def convert_to_proper_indexer_list(indexers_list):
    indexers_list_array = indexers_list.split(",")
    indexers_list_converted = str(indexers_list_array).replace("'","\"")
    return indexers_list_converted


def check_indexer_name(indexer_id):
    payload = {"userParams":{"queryParams":{"length":0},"headersParams":{"length":0},"cookiesParams":{"length":0},"bodyParams":{"length":0},"graphQLVariablesParams":{"0":indexer_id,"length":1}},"password":"","environment":"production","queryType":"GraphQLQuery","frontendVersion":"1","releaseVersion":"null","includeQueryExecutionMetadata":"false"}
    logger.debug("payload: ")
    logger.debug(payload)
    try:
        request = requests.post("https://ryabina.retool.com/api/public/7ddae5d0-b382-458a-9492-bec91c817ae4/query?queryName=checkInLocks", json=payload)
        response = json.loads(request.text)
        logger.debug("response: ")
        logger.debug(response)
    except:
        logger.error(request.status_code)
    try:
        ben_check = response["queryData"]["data"]["tokenLockWallet"]["beneficiary"]
        logger.debug("ben_check: ")
        logger.debug(ben_check)
        ben_addr = True
        logger.debug("ben_addr: ")
        logger.debug(ben_addr)
    except:
        ben_addr = False
        logger.debug(ben_addr)
        answer = -1
    if ben_addr == True:
        payload_name = {"userParams":{"queryParams":{"length":0},"headersParams":{"length":0},"cookiesParams":{"length":0},"bodyParams":{"length":0},"graphQLVariablesParams":{"0":response["queryData"]["data"]["tokenLockWallet"]["beneficiary"],"length":1}},"password":"","environment":"production","queryType":"GraphQLQuery","frontendVersion":"1","releaseVersion":"null","includeQueryExecutionMetadata":"false"}
        request_status = requests.post("https://ryabina.retool.com/api/public/ee3e8b77-0af5-4cfd-8d07-25ac6c6656d5/query?queryName=getBeneficiaryName", json=payload_name)
        responce_name = json.loads(request_status.text)
        logger.debug("payload_name: ")
        logger.debug(payload_name)
        logger.debug("request_status: ")
        logger.debug(request_status)
        logger.debug("responce_name: ")
        logger.debug(responce_name)
        try:
            indexer_name = responce_name["queryData"]["data"]["graphAccount"]["defaultName"]["name"]
            logger.debug("indexer_name: ")
            logger.debug(indexer_name)
            answer = 0
        except:
            logger.debug("Can't get valid indexer_name")
            indexer_name = "NoName"
            answer = -1
        logger.debug(answer)
    else:
        indexer_name = "NoName"

    if answer == -1:
        try:
            with open('indexers_list', 'r') as f:
                logger.debug("Search in indexer file")
                logger.debug("Indexer id is: ")
                logger.debug(i["indexer_id"])
                lines = f.read()
                indexer_check = lines.find(i["indexer_id"])
                logger.debug("indexer_check is: ")
                logger.debug(indexer_check)
                if indexer_check > -1:
                    logger.debug("Found an indexer in the list")
                    answer = 1
                    end_of_separator = lines.find('=', indexer_check)
                    end_of_line = lines.find('\n', indexer_check)
                    indexer_name = (lines[end_of_separator + 1:end_of_line])
        except:
            logger.warning("Can't open indexers_list file, skip ...")
            indexer_name = "NoName"
    logger.debug("answer is ")
    logger.debug(answer)

    return indexer_name


if __name__ == "__main__":
    logging_func()
    logger.info('Starting logging function')
    parser = argparse.ArgumentParser()
    parser.add_argument('--subgraph_ipfs_hash',
                        help='subgraph ipfs_hash to analyze',
                        required=True,
                        type=str)
    parser.add_argument('--graph_endpoint',
                        help='graph network endpoint (default: %(default)s)',
                        default='https://gateway.network.thegraph.com/network',
                        type=str)
    parser.add_argument('--local_index_node_endpoint',
                        help='local index node endpoint (default: %(default)s)',
                        default='http://graph-index-node:8030/graphql',
                        type=str)
    parser.add_argument('--block_hash_endpoint',
                        help='ethereum endpoint to request block hash (default: %(default)s)',
                        default='https://eth-mainnet.alchemyapi.io/v2/demo',
                        type=str)
    parser.add_argument('--number_allocation_to_check',
                        help='number of last closed allocation to check poi (default: %(default)s)',
                        default=10,
                        type=int)
    parser.add_argument('--indexers_list',
                        help='comma separated list of indexers to check poi with (default: %(default)s)',
                        default="all",
                        type=str)
    parser.add_argument('--no-zero-pois',
                        help='do not include allocations with zero pois (default: %(default)s)',
                        action='store_true')
    parser.add_argument('--my_indexer_id',
                        help='You can get info about your indexer if you want. (default: %(default)s)',
                        default="",
                        type=str)
    args = parser.parse_args()

    subgraph_ipfs_hash = args.subgraph_ipfs_hash
    graph_endpoint = args.graph_endpoint
    local_index_node_endpoint = args.local_index_node_endpoint
    block_hash_endpoint = args.block_hash_endpoint
    number_allocation_to_check = args.number_allocation_to_check
    indexers_list = convert_to_proper_indexer_list(args.indexers_list)
    indexer_id_arg = args.my_indexer_id

    if args.no_zero_pois:
        zero_pois = 'poi_not: "0x0000000000000000000000000000000000000000000000000000000000000000",'
    else:
        zero_pois = ""

    print()
    logger.info('Start to check POI for subgraph: {}'.format(subgraph_ipfs_hash))

    subgraph_deployment_id = to_id(subgraph_ipfs_hash)
    current_epoch = get_current_epoch()
    logger.info("Current Epoch: {}".format(current_epoch))

    indexers_poi_epoch = get_indexers_poi_epoch(subgraph_deployment_id, zero_pois)

    if indexer_id_arg != "":
        indexer_id = indexer_id_arg.lower()
        start_block = get_start_block(current_epoch)
        start_block_hash = get_start_block_hash(start_block)
        my_poi = generate_poi(indexer_id, start_block, start_block_hash, subgraph_ipfs_hash)
        logger.info("Your latest POI is " + str(my_poi) + " for epoch: " + str(current_epoch))

        previous_start_block = get_start_block(current_epoch-1)
        previous_start_block_hash = get_start_block_hash(previous_start_block)
        previous_my_poi = generate_poi(indexer_id, previous_start_block, previous_start_block_hash, subgraph_ipfs_hash)
        logger.info("Your previous POI is " + str(previous_my_poi) + " for epoch: " + str(current_epoch-1))
    else:
        logger.info("You can use --my_indexer_id to get more info")

    for i in indexers_poi_epoch:
        start_block = get_start_block(i["epoch"])
        start_block_hash = get_start_block_hash(start_block)
        my_poi = generate_poi(i["indexer_id"], start_block, start_block_hash, subgraph_ipfs_hash)
        check_indexer_name_result = check_indexer_name(i["indexer_id"])

        print()
        if my_poi != i["poi"]:
            previous_start_block = get_start_block(i["epoch"]-1)
            previous_start_block_hash = get_start_block_hash(previous_start_block)
            previous_my_poi = generate_poi(i["indexer_id"], previous_start_block, previous_start_block_hash, subgraph_ipfs_hash)
            logger.debug("Previous_my_poi is " + str(previous_my_poi))
            if previous_my_poi != i["poi"]:
                logger.info("FAILED: POI missmatched with indexer " + i["indexer_id"] + " (" + check_indexer_name_result + "). Generated POI: {1} Indexer POI: {2} Allocation was closed in {3} EPOCH. Allocated Tokens: {4}". format(i["indexer_id"], my_poi, i["poi"], i["epoch"], i["allocatedTokens"]))
            else:
                logger.info("OK: POI matched with indexer " + i["indexer_id"] + " (" + check_indexer_name_result + ") for epoch {2}. Allocation was closed in {1} EPOCH. Allocated Tokens: {3}".format(i["indexer_id"], i["epoch"], i["epoch"]-1, i["allocatedTokens"]))
        else:
            logger.info("OK: POI matched with indexer " + i["indexer_id"] + " ("  + check_indexer_name_result + "). Allocation was closed in {1} EPOCH. Allocated Tokens: {2}".format(i["indexer_id"], i["epoch"], i["allocatedTokens"]))

