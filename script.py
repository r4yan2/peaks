#!/usr/bin/python3
import peewee
from peewee import *
from mymodels import Ptree
from collections import defaultdict
from matplotlib import pyplot as plt
from graphviz import Digraph

#calculating stuff
#fetching nodes key

nodes = Ptree.select(Ptree.node_key)
node_keys = [node.node_key for node in nodes]

## Number of nodes

node_number = len(node_keys)

## heigth of tree

tree_heigth = int(max([len(key) for key in node_keys])/2) + 1

## arity(fixed)

arity = 4

## nodes per level

#lv: proper_node,leaf_node
nodes_lv = {}

leaf_node_query = Ptree.select().where(Ptree.leaf == True)
leaf = [node.node_key for node in leaf_node_query]


leafonlv = defaultdict(lambda: [])

for l in leaf:
    leafonlv[len(l)/2].append(l)

nodes_lv[0] = 1
proper_nodes_on_prev_lv = 1
for lv in range(1, tree_heigth):
    leaf_nodes_on_lv = len(leafonlv[lv])
    nodes_on_lv = proper_nodes_on_prev_lv * arity

    #despite the name it is referred to current lv
    proper_nodes_on_prev_lv = nodes_on_lv - leaf_nodes_on_lv
    nodes_lv[lv] = nodes_on_lv 
    print("lv", lv, ": leaf_nodes_on_lv", leaf_nodes_on_lv, "proper_nodes_on_lv", proper_nodes_on_prev_lv)


## stats for balancing and branch height
child_prefix = {"00": [], "01": [], "10": [], "11" : []}
### and dot graph generation in piggybacking
dot = Digraph(comment='pTree representation')
dot.node(node_keys[0], node_keys[0])
for key in node_keys[1:]:
    child_prefix[key[:2]].append(len(key)//2)
    if len(key) <= 8:
        dot.node(key, key)
        dot.edge(key[:len(key)-2], key)

dot.render('ptree.gv', view=True)

heights = [max(key_lengths) for key_lengths in child_prefix.values()]
min_height_subtree = min(heights)
max_height_subtree = max(heights)
avg_height_subtree = round(sum(heights)/len(heights), 2)

## stats of leaf nodes
num_elements = [node.num_elements for node in leaf_node_query]
max_num_elements = max(num_elements)
min_num_elements = min(num_elements)
mean_num_elements = round(sum(num_elements)/len(num_elements), 2)
variance_num_elements = round(sum((map(lambda x: (x - mean_num_elements)**2, num_elements)))/len(num_elements), 2)

bins = range(0, 101, 10)
plt.xlim([min(num_elements)-5, max(num_elements)+5])
#plt.xlim([min(bins)-5, max(bins)+5])
plt.hist(num_elements, bins=bins, histtype='bar', alpha=0.8)
plt.title("distributions of #elements per leaf node")
plt.xlabel("bins")
plt.ylabel("#elements")
plt.grid(True)
ax = plt.gca()
ax.set_yscale('log')
plt.savefig("elementsxnode.svg")

## output

assert (sum(nodes_lv.values()) == node_number), "sum(Nodes x lv) != total nodes"
print("Stats of current tree:")
print("arity", arity)
print("node_number", node_number)
print("tree_heigth", tree_heigth)
print("nodes per lv", nodes_lv)
print("max_num_elements", max_num_elements)
print("min_num_elements", min_num_elements)
print("avg_num_elements", mean_num_elements)
print("variance_num_elements", variance_num_elements)
print("min_heigth subtree", min_height_subtree)
print("max_heigth  subtree", max_height_subtree)
print("tree is balanced?", min_height_subtree==max_height_subtree)
