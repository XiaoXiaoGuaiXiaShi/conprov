#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/3/27 下午3:51
# @Author  : dqq
# @File    : spade_graph.py
import argparse
import json
import time

import graphviz
import networkx as nx

from capabilities_define import cap_hex_parser, diff_cap, cap_name, syscall_name
from process_log import process_data

default_cap = {"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
               "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
               "CAP_NET_RAW", "CAP_SYS_CHROOT", "CAP_MKNOD", "CAP_AUDIT_WRITE", "CAP_SETFCAP"}


def spade_graph(vertices, edges):
    provG = nx.MultiDiGraph()

    for vertex in vertices:
        nid = vertex["id"]
        label_dict = vertex["annotations"]

        if vertex["type"] == "Entity":
            provG.add_node(nid, prov_type="Entity", label="Entity")
            provG.nodes[nid]["anomalous"] = 0
            if "object_type" in label_dict.keys():
                if label_dict["object_type"] == "path" and "pathname" in label_dict.keys():
                    provG.nodes[nid]["label"] = label_dict["object_type"] + ":" + label_dict["pathname"]
                elif label_dict["object_type"] == "address" and "host" in label_dict.keys() and "type" in label_dict.keys() and "service" in label_dict.keys():
                    provG.nodes[nid]["label"] = label_dict["object_type"] + ":" + str(label_dict["host"]) + " " + str(label_dict["service"]) + " " + str(label_dict["type"])
                elif label_dict["object_type"] == "process_memory":
                    cap_str = label_dict["CapEff1"][2:] + label_dict["CapEff0"][2:]
                    capTextList = cap_hex_parser(cap_str)
                    diff_cap_list = diff_cap(default_cap, capTextList)
                    if "comm" in label_dict.keys():
                        provG.nodes[nid]["label"] = label_dict["object_type"] + ":" + str(label_dict["pid"]) + " " + str(label_dict["comm"])
                    else:
                        provG.nodes[nid]["label"] = label_dict["object_type"] + ":" + str(label_dict["pid"])
                    if len(diff_cap_list) != 0:
                        provG.nodes[nid]["label"] = provG.nodes[nid]["label"] + "\n" + "capabilities: " + str(diff_cap_list)
                elif label_dict["object_type"] == "file" or label_dict["object_type"] == "socket":
                    provG.nodes[nid]["label"] = label_dict["object_type"] + ":ino " + str(label_dict["ino"])
                else:
                    provG.nodes[nid]["label"] = label_dict["object_type"]
        elif vertex["type"] == "Activity":
            provG.add_node(nid, prov_type="Activity", label="Activity")
            provG.nodes[nid]["anomalous"] = 0
            if "object_type" in label_dict.keys():
                if label_dict["object_type"] == "task" and "tid" in label_dict.keys():
                    cap_str = label_dict["CapEff1"][2:] + label_dict["CapEff0"][2:]
                    capTextList = cap_hex_parser(cap_str)
                    diff_cap_list = diff_cap(default_cap, capTextList)
                    # if len(diff_cap_list) == 0:
                    provG.nodes[nid]["label"] = label_dict["object_type"] + ":" + str(label_dict["pid"]) + " " + str(label_dict["comm"])
                    # else:
                    #     provG.nodes[nid]["label"] = label_dict["object_type"] + ":" + str(label_dict["pid"]) + " " + str(label_dict["comm"]) + "\n" + "capabilities: " + str(diff_cap_list)
            if "version" in label_dict.keys():
                provG.nodes[nid]["label"] = provG.nodes[nid]["label"] + "\n" + "version:" + str(label_dict["version"])
            # provG.nodes[nid]["label"] = provG.nodes[nid]["label"] + " object_id:" + str(label_dict["object_id"])
        # we don't collect agent, but write down in advance in case we collect for the future

    for edge in edges:
        u = edge["from"]
        v = edge["to"]
        relation = edge["relation_type"] if "relation_type" in edge.keys() else edge["type"]
        cap = edge["cap"] if "cap" in edge.keys() else "3e8"
        if cap == "3e8":
            provG.add_edge(
                u,
                v,
                relation_type=relation,
                time=edge["cf:date"],
                label=edge["from_type"] + " " + relation + " " + edge["to_type"],
                anomalous=0
            )
        else:
            provG.add_edge(
                u,
                v,
                relation_type=relation,
                time=edge["cf:date"],
                label=edge["from_type"] + " " + relation + " " + edge["to_type"] + "\n cap:" + cap_name[str(edge["cap"])] + "\n syscall_nid:" + syscall_name[edge["syscall"]],
                anomalous=0
            )

    # remove edges without src or dst nodes
    remove_bad_edges = []
    for edge in provG.edges.data(keys=True):
        src, dst, key, attr = edge
        if provG.nodes[src] == {}:
            remove_bad_edges.append(src)
        elif provG.nodes[dst] == {}:
            remove_bad_edges.append(dst)
    provG.remove_nodes_from(remove_bad_edges)

    # remove isolated nodes
    remove_bad_nodes = []
    for nid in provG.nodes:
        if list(provG.successors(nid)) == [] and list(provG.predecessors(nid)) == []:
            remove_bad_nodes.append(nid)
    provG.remove_nodes_from(remove_bad_nodes)

    return provG


def write_graphviz(graph):
    g = graphviz.Digraph()
    for nid in graph.nodes:
        nid_str = nid.replace("=", "")
        if graph.nodes[nid]:
            if graph.nodes[nid]["prov_type"] == 'Activity':
                if 'capabilities' in graph.nodes[nid]["label"]:
                    g.attr('node', shape='box', color='LightCoral', style='filled')
                else:
                    g.attr('node', shape='box', color='lightblue', style='filled')
                g.node(nid_str, label=graph.nodes[nid]["label"])
            elif graph.nodes[nid]["prov_type"] == 'Entity':
                if 'socket' in graph.nodes[nid]["label"] or 'file' in graph.nodes[nid]["label"]:
                    g.attr('node', shape='ellipse', color='lightyellow', style='filled')
                    g.node(nid_str, label=graph.nodes[nid]["label"])
                elif 'path' in graph.nodes[nid]["label"] or 'address' in graph.nodes[nid]["label"]:
                    g.attr('node', shape='diamond', color='lightpink', style='filled')
                    g.node(nid_str, label=graph.nodes[nid]["label"])
                # elif 'capabilities' in graph.nodes[nid]["label"]:
                #     g.attr('node', shape='box', color='LightCoral', style='filled')
                #     g.node(nid_str, label=graph.nodes[nid]["label"])
                else:
                    g.attr('node', shape='box', color='lightblue', style='filled')
                    g.node(nid_str, label=graph.nodes[nid]["label"])

    for (u, v, k) in graph.edges:
        u_str = u.replace("=", "")
        v_str = v.replace("=", "")
        if "\n cap:" in graph.edges[u, v, k]["label"]:
            g.edge(u_str, v_str, label=graph.edges[u, v, k]["label"], color='red')
        else:
            g.edge(u_str, v_str, label=graph.edges[u, v, k]["label"])

    g.render('graph', format='pdf', cleanup=True, outfile="conprov.pdf")


if __name__ == '__main__':
    start = time.time()
    input_path = "conprov.log"
    vertices, edges = process_data(input_path)
    print("Finish loading spade logs!\n")

    graph = spade_graph(vertices, edges)
    print("finish handling with spade graph!\n")

    write_graphviz(graph)
    print("finish writing graphviz!\n")

    end = time.time()
    print("Spend time: " + str(end - start))
