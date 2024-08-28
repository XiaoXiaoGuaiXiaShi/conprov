#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/12/25 14:12
# @Author  : dqq
# @File    : process_log.py
import json
from collections import defaultdict


def get_keys(d, value):
    return [k for k,v in d.items() if v == value]


def get_new(nodes, edges, nodes_id, replace_node):
    # new_file = open(output_path, "a+")
    new_nodes = []
    new_edges = []
    for id in nodes_id.keys():
        for node in nodes:
            if node["id"] in nodes_id[id]:
                new_node = node
                new_node["id"] = id
                new_nodes.append(new_node)
                # new_file.write(str(new_node) + "\n")
                break
    for edge in edges:
        new_edge = {}
        if edge["from"] in replace_node:
            new_edge['from'] = replace_node[edge["from"]]
        else:
            new_edge['from'] = edge["from"]

        if edge["to"] in replace_node:
            new_edge['to'] = replace_node[edge["to"]]
        else:
            new_edge['to'] = edge["to"]

        new_edge["cf:date"] = edge["annotations"]["cf:date"]
        new_edge["relation_type"] = edge["annotations"]["relation_type"]
        new_edge["from_type"] = edge["annotations"]["from_type"]
        new_edge["to_type"] = edge["annotations"]["to_type"]
        new_edge["cap"] = edge["annotations"]["cap"]
        new_edge["syscall"] = edge["annotations"]["syscall"]
        for id in nodes_id.keys():
            if edge["from"] in nodes_id[id]:
                new_edge["from"] = id
            if edge["to"] in nodes_id[id]:
                new_edge["to"] = id
        if new_edge not in new_edges:
            new_edges.append(new_edge)
    # for new in new_edges:
    #     new_file.write(str(new) + "\n")
    # new_file.close()
    return new_nodes, new_edges


def process_data(input_path):
    # input_path = "repeated_conprov.log"
    # output_path = "new.log"
    log = open(input_path, 'r', encoding="utf-8")
    nodes = []
    edges = []
    nodes_id = defaultdict(list)
    nodes_attr = defaultdict()
    node_id = 0
    line = log.readline()
    replace_node = defaultdict()
    while line:
        if "[" in line or "]" in line:
            line = log.readline()
            continue
        if line[0] == "," or line[0] == " ":
            line = line[1:]
        if line[0] == "\n":
            line = log.readline()
            continue
        data = json.loads(line)
        if "from" not in data.keys():
            if data["annotations"]["object_type"] == "path" and "pathname" in data["annotations"].keys():
                attr = [data["annotations"]["object_type"], data["annotations"]["cf:date"], "pid", "comm",
                        data["annotations"]["pathname"]]
            elif data["annotations"]["object_type"] == "task" and "comm" in data["annotations"].keys():
                attr = [data["annotations"]["object_type"], data["annotations"]["cf:date"], data["annotations"]["pid"],
                        data["annotations"]["comm"],
                        "pathname"]
            elif data["annotations"]["object_type"] == "process_memory" and "comm" in data["annotations"].keys():
                attr = [data["annotations"]["object_type"], data["annotations"]["cf:date"],
                        data["annotations"]["pid"], data["annotations"]["comm"],
                        "pathname"]
            else:
                attr = [data["annotations"]["object_type"], data["annotations"]["cf:date"], "pid", "comm", "pathname"]
            if attr in nodes_attr.values():
                id = get_keys(nodes_attr, attr)
                nodes_id[id[0]].append(data["id"])
            else:
                nodes_id[str(node_id)].append(data["id"])
                nodes_attr[str(node_id)] = attr
                node_id += 1
            nodes.append(data)
        else:
            if data["annotations"]["relation_type"] == "version_entity":
                replace_node[data["to"]] = data["from"]
            edges.append(data)
        line = log.readline()
    print("generating new nodes and edges......\n")
    new_nodes, new_edges = get_new(nodes, edges, nodes_id, replace_node)
    log.close()
    return new_nodes, new_edges
