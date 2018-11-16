#!/usr/bin/python2
from peewee import *
from mymodels import database, Ptree, GpgKeyserver, Userattribute, Userid
from collections import defaultdict
from matplotlib import pyplot as plt
#from graphviz import Digraph
import argparse
import multiprocessing as multi
import dns
import smtplib
import re

#calculating stuff

def ptree(args):
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
        print "lv", lv, ": leaf_nodes_on_lv", leaf_nodes_on_lv, "proper_nodes_on_lv", proper_nodes_on_prev_lv
    
    
    ## stats for balancing and branch height
    child_prefix = {"00": [], "01": [], "10": [], "11" : []}
    ### and dot graph generation in piggybacking
    #dot = Digraph(comment='pTree representation')
    #dot.node(node_keys[0], node_keys[0])
    for key in node_keys[1:]:
        child_prefix[key[:2]].append(len(key)//2)
        #if len(key) <= 4:
        #    dot.node(key, key)
        #    dot.edge(key[:len(key)-2], key)
    
    #dot.render('ptree.gv', view=args.view)
    
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
    if args.view:
        plt.show()
    plt.savefig("elementsxnode.svg")
    
    ## output
    
    print "Stats of current tree:"
    print "arity", arity
    print "node_number", node_number
    print "tree_heigth", tree_heigth
    print "nodes per lv", nodes_lv
    print "max_num_elements", max_num_elements
    print "min_num_elements", min_num_elements
    print "avg_num_elements", mean_num_elements
    print "variance_num_elements", variance_num_elements
    print "min_heigth subtree", min_height_subtree
    print "max_heigth  subtree", max_height_subtree
    print "tree is balanced?", min_height_subtree==max_height_subtree

def certificates(args):
    ## get certificate dimensions
    
    certificates = GpgKeyserver.select(fn.OCTET_LENGTH(GpgKeyserver.certificate).alias("certificate_length"))
    num_certificates = len(certificates)
    data = sorted([int(certificate.certificate_length) for certificate in certificates])
    
    KB = 1024
    MB = KB * 1024
    sub_10kb_bin = range(0, 10*KB, KB)
    from_10_to_100_kb_bin = range(10*KB, 100*KB, 10*KB)
    from_100kb_to_1M_bin = range(100*KB, MB, 100*KB)
    
    bins = sub_10kb_bin + from_10_to_100_kb_bin + from_100kb_to_1M_bin
    #bins = sub_10kb_bin + from_10_to_100_kb_bin
    #bins = sub_10kb_bin
    
    i=0
    buckets = []
   
    for limit in bins:
        bucket = []
        try:
            while data[i] < limit:
                bucket.append(data[i])
                i+=1
            buckets.append(len(bucket))
        except IndexError:
            buckets.append(len(bucket))
            break

    ticks = [str(step//KB) for step in bins]
    
    #plt.hist(data, bins=bins, histtype='bar')
    plt.bar(range(len(buckets)), buckets, align='edge', width=-1)
    plt.title("distributions of certificates length")
    plt.xlabel("bins (KB)")
    plt.ylabel("cert length")
    plt.xticks(range(len(buckets)), ticks)
    plt.xticks(rotation=45)
    #plt.yticks(5, [1, 10, 100, 1000, 10000])
    #plt.grid(True)
    #ax = plt.gca()
    #ax.set_yscale('linear')
    #ax.set_xticks(ticks)
    #ax.set_xticklabels(ticks)
    if args.view:
        plt.show()
    plt.savefig("certificates_length.svg")
    plt.clf()

    #certificates with user attributes
    user_attr = [(int(res.length), bool(res.is_image)) for res in Userattribute.select(fn.OCTET_LENGTH(Userattribute.image).alias("length"), Userattribute.is_image)]

    num_certificates_with_user_attr = len(user_attr)

    i = round(num_certificates_with_user_attr*100/num_certificates, 4)
    j = 100 - i

    labels = ("certificates with user attributes","certificates")
    explode = (0.2,0)
    fig1, ax1 = plt.subplots()
    ax1.pie([i,j], explode=explode, labels=labels, autopct='%1.1f%%',
                    shadow=True, startangle=90)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

    if args.view: 
        plt.show()
    plt.savefig("certificates_user_attr.svg")

    plt.clf()

    #division of user attributes
    image_user_attributes = len([l for l,is_image in user_attr if is_image])
    i = round(image_user_attributes*100/num_certificates_with_user_attr, 4)
    j = 100 -i

    labels = ("image user attributes","other user attributes")
    explode = (0,0.2)
    fig1, ax1 = plt.subplots()
    ax1.pie([i,j], explode=explode, labels=labels, autopct='%1.1f%%',
                    shadow=True, startangle=90)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

    if args.view: 
        plt.show()
    plt.savefig("user_attr_division.svg")

    plt.clf()

    data = [l for l,s in user_attr]
    max_data_len = max(data)
    KB = 1024
    MB = KB * 1024
    sub_10kb_bin = list(range(0, 10*KB, KB))
    from_10_to_100_kb_bin = list(range(10*KB, 100*KB, 10*KB))
    from_100kb_to_1M_bin = list(range(100*KB, MB, 100*KB))
    
    bins = sub_10kb_bin + from_10_to_100_kb_bin + from_100kb_to_1M_bin
    #bins = sub_10kb_bin + from_10_to_100_kb_bin
    #bins = sub_10kb_bin
    
    i=0
    buckets = []
    for limit in bins:
        bucket = []
        try:
            while data[i] < limit:
                bucket.append(data[i])
                i+=1
            buckets.append(len(bucket))
        except IndexError:
            buckets.append(len(bucket))
            break
   
    ticks = [str(step//KB) for step in bins]
    
    #plt.hist(data, bins=bins, histtype='bar')
    plt.bar(range(len(buckets)), buckets, align='edge', width=-1)
    plt.title("distributions of certificates length")
    plt.xlabel("bins (KB)")
    plt.ylabel("cert length")
    plt.xticks(range(len(buckets)), ticks)
    plt.xticks(rotation=45)
    #plt.yticks(5, [1, 10, 100, 1000, 10000])
    #plt.grid(True)
    #ax = plt.gca()
    #ax.set_yscale('linear')
    #ax.set_xticks(ticks)
    #ax.set_xticklabels(ticks)
    if args.view:
        plt.show()
    plt.savefig("user_attributes_length.svg")
    plt.clf()


def userid(args):
    down = set()
    host_address_dict = defaultdict(lambda: [])
    ##fetching email
    query = database.execute_sql("SELECT FROM_BASE64(name), FROM_BASE64(email) FROM UserID")
    ok = 0
    PPA = 0
    no_mail = 0
    url = []
    i = query.rowcount
    while i > 0:
        res = query.fetchone()
        name = decode(res[0])
        email = decode(res[1])
        i -= 1
        if "PPA" in name or "Launchpad" in name:
            PPA += 1
        try:
            re.findall("(https?|ftp)://[^/\r\n]+/[^\r\n]*?", name)[0]
            url.append(name)
        except IndexError:
            pass
        if email == "":
            no_mail += 1
            continue
        name, host = email.split("@")
        host_address_dict[host].append(name)
    print "PPA found: ", PPA
    print "Pubkey with no mail: ", no_mail
    print "Domains found: ", len(host_address_dict.keys())

    """ 
    for host in host_address_dict.iterkeys():
        try:
            records = dns.resolver.query(host, "MX")
            for name in host_address_dict[host]:
                if verify_mail(records, name+"@"+host):
                    ok += 1
        except NXDOMAIN:
            down.add(host)
    """

def decode(unistr):
    try:
        return unistr.decode()
    except UnicodeDecodeError:
        return unistr.decode('unicode-escape')
    except AttributeError:
        return ""

def verify_mail(records, email):
    mxRecord = records[0].exchange
    mxRecord = str(mxRecord)
    
    #Step 3: ping email server
    #check if the email address exists
    
    # Get local server hostname
    host = socket.gethostname()
    
    # SMTP lib setup (use debug level for full output)
    server = smtplib.SMTP()
    server.set_debuglevel(0)
    
    # SMTP Conversation
    server.connect(mxRecord)
    server.helo(host)
    server.mail('grazioandre@gmail.com')
    code, message = server.rcpt(email)
    server.quit()
    
    return code == 250

func_dictionary = {
        'ptree': ptree,
        'certificates': certificates,
        'userid': userid
        }

long_desc="""
Utility script to dump information about
the current keyserver infrastructure.
Needs Mysql running and initialized with certificates

 * Sanity della struttura del PTree
  ok altezza (massima)/ numero complessivo di nodi
  ok coefficiente di bilanciamento
  ok nodi per livello
  ok foglie per nodo padre-di-foglia (istogramma con distribuzione)

 * Sanity (di formato/sintattica) dei certificati
  -- # di certificati che non sarebbero neppure parsabili / certificati
totali per anno di creazione
  ok # di certificati per dimensione (bin da 10 kiB per iniziare, sui
primi 10 kB, bin da 1kiB)
  ok #di certificati con user attributes fotografici, #di cert con user
attributes di altro tipo, rispetto al totale dei certificati
  ok dimensioni degli user attributes

 * Security state
  -- Algoritmi usati per encryption e per signature (per anno)
  -- Dimensione delle chiavi (per anno)
  -- Signatures valide / self signatures valide sul totale
  -- Attacchi da formato : curve inesistenti
  -- Attacchi da analyzer: moduli RSA con fattori piccoli/primi

 * Liveness/usage state
  wip # user ID che contengono un indirizzo mail (da regex, istogramma
sovrapposto con i numeri assoluti)
  wip mail domains: statistiche di frequenza, gli MX esistono ancora?


"""
parser = argparse.ArgumentParser(description=long_desc)
parser.add_argument('--multi', action='store_true', help='activate parallelism')
parser.add_argument('--view', action='store_true', help='see generated graphics now')
parser.add_argument('command', help='which analysis to run')
args = parser.parse_args()
print(args)
if args.command == 'all':
    if args.multi:
        p=multi.Pool(processes=multi.cpu_count()-1)
        p.map(lambda x: x(args), func_dictionary.values())
    else:
        [f(args) for f in func_dictionary.values()] 
else:
    try:
        func_dictionary[args.command](args)
    except KeyError:
        print "Command not recognized"
