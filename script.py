#!/usr/bin/python2
from mymodels import *
from collections import defaultdict, Counter
from operator import itemgetter
from matplotlib import pyplot as plt
from graphviz import Digraph
import argparse
import multiprocessing as multi
import csv
import dns
import smtplib
import re
import numpy as np
from datetime import datetime

def plot_ptree(_):
    fp = open('data/ptree_elements_per_node.csv', 'rb')
    text = fp.readline()
    fp.close()
    num_elements = [int(num) for num in text.split(',')]

    bins = range(0, 101, 10)
    plt.xlim([min(num_elements)-5, max(num_elements)+5])
    plt.hist(num_elements, bins=bins, histtype='bar', alpha=0.8)
    plt.title("distributions of #elements per leaf node")
    plt.xlabel("bins")
    plt.ylabel("#elements")
    plt.grid(True)
    ax = plt.gca()
    ax.set_yscale('log')
    if args.view:
        plt.show()
    plt.savefig("data/ptree/elementsxnode.svg")
    plt.clf()
    print "Saved", "elementsxnode.svg"
    
def plot():
    fp = open('data/certificates_length.csv', 'rb')
    text = fp.readline()
    fp.close()
    data = [int(num) for num in text.split(',')]

    KB = 1024
    MB = KB * 1024
    sub_10kb_bin = range(0, 10*KB, KB)
    from_10_to_100_kb_bin = range(10*KB, 100*KB, 10*KB)
    from_100kb_to_1M_bin = range(100*KB, MB, 100*KB)

    bins = sub_10kb_bin + from_10_to_100_kb_bin + from_100kb_to_1M_bin
    
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
 
    plt.bar(range(len(buckets)), buckets, align='edge', width=-1)
    plt.title("distributions of certificates length")
    plt.xlabel("bins (KB)")
    plt.ylabel("cert length")
    plt.xticks(range(len(buckets)), ticks)
    plt.xticks(rotation=45)
    if args.view:
        plt.show()
    plt.savefig("certificates_length.svg")
    plt.clf()
    print "Saved", "certificates_length.svg"

    fp.open('data/certificates_with_user_attributes', 'rb')
    text = fp.readline()
    fp.close()

    data = [int(length) for length in text.split(',')]
    max_data_len = max(data)
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
    
    plt.bar(range(len(buckets)), buckets, align='edge', width=-1)
    plt.title("distributions of certificates length")
    plt.xlabel("bins (KB)")
    plt.ylabel("cert length")
    plt.xticks(range(len(buckets)), ticks)
    plt.xticks(rotation=45)
    if args.view:
        plt.show()
    plt.savefig("user_attributes_length.svg")
    plt.clf()
    print "Saved", "user_attributes_length.svg"


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
        #print "lv", lv, ": leaf_nodes_on_lv", leaf_nodes_on_lv, "proper_nodes_on_lv", proper_nodes_on_prev_lv
    
    
    ## stats for balancing and branch height
    child_prefix = {"00": [], "01": [], "10": [], "11" : []}
    ### and dot graph generation in piggybacking
    dot = Digraph(comment='pTree representation')
    dot.node(node_keys[0], node_keys[0])
    for key in node_keys[1:]:
        child_prefix[key[:2]].append(len(key)//2)
        if len(key) <= 4:
            dot.node(key, key)
            dot.edge(key[:len(key)-2], key)
    
    dot.render('data/ptree/ptree.gv', view=args.view)
    
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
    
    fp = open('data/ptree/ptree_elements_per_node.csv', 'w', 0)
    fp.write(','.join(marshal(num_elements)))
    fp.close()

    ## output

    fp = open('data/ptree/ptree_status.csv', 'w', 0)
    writer = csv.writer(fp, delimiter=',', quoting=csv.QUOTE_NONE)
    data = (
            ("arity", arity),
            ("node_number", node_number),
            ("leaf_node_number", len(leaf)),
            ("tree_heigth", tree_heigth),
            ("max_num_elements", max_num_elements),
            ("min_num_elements", min_num_elements),
            ("avg_num_elements", mean_num_elements),
            ("variance_num_elements", variance_num_elements),
            ("min_heigth subtree", min_height_subtree),
            ("max_heigth  subtree", max_height_subtree),
            ("tree is balanced", min_height_subtree==max_height_subtree)
            )
    writer.writerows(data)
    fp.close()

    fp = open('data/ptree/ptree_nodes-per_level.csv', 'w', 0)
    writer = csv.writer(fp, delimiter=',', quoting=csv.QUOTE_NONE)
    header = ["lv", "nodes"]
    writer.writerow(header)
    writer.writerows(nodes_lv.items())
    fp.close()

def certificates(args):
    ## get certificate dimensions
    
    certificates = GpgKeyserver.select(fn.OCTET_LENGTH(GpgKeyserver.certificate).alias("certificate_length"))
    num_certificates = len(certificates)
    data = sorted([int(certificate.certificate_length) for certificate in certificates])
    
    data = ','.join(marshal(data))
    fp = open('data/certificates_length.csv', 'w', 0)
    fp.write(data)
    fp.close()

    #certificates with user attributes
    user_attr = [(int(res.length), bool(res.is_image)) for res in Userattribute.select(fn.OCTET_LENGTH(Userattribute.image).alias("length"), Userattribute.is_image)]

    num_certificates_with_user_attr = (len(user_attr)*100.0/num_certificates, "certificates with user attributes", 0.2)

    total = (100 - num_certificates_with_user_attr, "certificates", 0.0)

    bake((num_certificates_with_user_attr, total), "certificates_user_attr.svg")

    #division of user attributes
    image_user_attributes = len([l for l,is_image in user_attr if is_image])
    image_user_attributes = (image_user_attributes*100.0/num_certificates_with_user_attr, "image_user_attributes", 0.0)
    other = (100-image_user_attributes, "other_user_attributes", 0,2)

    bake((image_user_attributes, other), "user_attr_division.svg")

    data = [l for l,s in user_attr]
    fp = open('data/certificates_with_user_attributes', 'w', 0)
    fp.write(','.join(marshal(data)))
    fp.close()

def marshal(data):
    return (str(d) for d in data)

def userid(args):
    down = set()
    ##fetching email
    query = database.execute_sql("SELECT ownerkeyid, FROM_BASE64(name) FROM UserID")
    PPA_w_mail = 0
    PPA_no_mail = 0
    no_mail = 0
    url = []
    chinese_names = []
    chinese_years = []
    chinese_ids = []
    hosts = []
    total_userid = query.rowcount
    i = query.rowcount
    domain_dict = defaultdict(lambda: [])
    while i > 0:
        res = query.fetchone()
        keyid = res[0]
        name = decode(res[1])
        i -= 1
        try:
            email = re.findall("[\w_.+-]+@[a-zA-Z0-9.-]+[a-zA-Z]+", name)[0]
            if "PPA" in name or "Launchpad" in name:
                PPA_w_mail += 1
        except IndexError:
            email = ""
            if len(name)==30 and all([c.isupper() for c in name]):
                chinese_names.append(name)
                chinese_ids.append(keyid)
                # number of chinese keys created in that year
                chinese_year.append(Pubkey.select(Pubkey.keyid, Pubkey.creationtime).where(Pubkey.keyid==keyid)[0].creationtime.year)
            elif "PPA" in name or "Launchpad" in name:
                PPA_no_mail += 1
            else:
                no_mail += 1
        try:
            re.findall("(https?|ftp)://[^/\r\n]+/[^\r\n]*?", name)[0]
            url.append(name)
        except IndexError:
            pass
        if email == "":
            continue
        name, host = email.split("@")
        domain_dict[host].append(name)

    chinese_year_counter = Counter(chinese_year)

    non_chinese_keys = Counter((pubkey.creationtime.year for pubkey in Pubkey.select(Pubkey.creationtime).where(Pubkey.keyid not in chinese_ids)))
    cur_year = datetime.now().year
    non_chinese_year_sorted = sorted([(y, c) for y, c in non_chinese_keys_ if y > 1980 and y < cur_year], key=itemgetter(0))
    all_keys_year_cumulative = []
    for i, year, count in enumerate(non_chinese_year_sorted):
        acc = 0
        while (i > 0):
            acc += non_chinese_year_sorted[i][1] + chinese_year_counter[year]
            i -= 1
        all_keys_year_cumulative.append((year, acc))
    
    fp = open('data/non_chinese_year_sorted', 'w', 0)
    writer = csv.writer(fp, delimiter=',', quoting=csv.QUOTE_NONE)
    writer.writerows(non_chinese_year_sorted)
    fp.close()

    fp = open('data/all_keys_year_cumulative' 'w', 0)
    writer = csv.writer(fp, delimiter=',', quoting=csv.QUOTE_NONE)
    writer.writerows(all_keys_year_cumulative)
    fp.close()

    fp = open('data/chinese_keys.csv', 'w', 0)
    writer = csv.writer(fp, delimiter=',', quoting=csv.QUOTE_NONE)
    header=["year", "count"]
    writer.writerow(header)
    writer.writerows(chinese_year_counter.items())
    fp.close()
    
    fp = open('data/chinese_names', 'w', 0)
    fp.write(marshal(chinese_names))
    fp.close() 

    domain_counter = [(d, len(n)) for d, n in domain_dict.items()]
    domain_sorted = sorted(domain_counter, key=itemgetter(1), reverse=True)

    fp = open('data/userid_stats', 'w', 0)
    writer = csv.writer(fp, delimiter=',', quoting=csv.QUOTE_NONE)
    data = (
            ("UserIDs registered: ", total_userid),
            ("PPA found: ", PPA_w_mail + PPA_no_mail),
            ("PPA with mail: ", PPA_w_mail),
            ("PPA without mail: ", PPA_no_mail),
            ("Pubkey with no mail: ", no_mail),
            ("Domains found: ", len(host_counter))
                )
    writer.writerows(data)
    fp.close()

    # PPA_mail, PPA_no_mail(intersect no_mail), no_mail_no_ppa, total
    PPA_tot = PPA_w_mail + PPA_no_mail
    pm = PPA_w_mail*100.0/PPA_tot
    pnm = 100 - pm

    pm = (pm, "PPA with mail", 0.0)
    pnm = (pnm, "PPA without mail", 0.0)
    
    bake([pm, pnm], "PPA_distribution.svg")

    #PPA_m = PPA_w_mail*100.0/total_userid
    #PPA_nm = PPA_no_mail*100.0/total_userid

    #PPA = (PPA_m + PPA_nm, "PPAs", 0.0)

    #no_mail = no_mail*100.0/total_userid
    #no_mail = (no_mail, "no mail", 0.0)

    #total = 100 - no_mail
    #total = (total, "UserIDs", 0.0)
    #bake((no_mail, total), "userid_distr.svg")
   
    #fig, ax = plt.subplots()    
    #width = 0.75 # the width of the bars 
    #ind = range(len(domains))  # the x locations for the groups
    #ax.barh(ind, nhosts, width, color="blue")
    #ax.set_yticks(ind)
    #ax.set_yticklabels(domains, minor=False)
    #ax.invert_yaxis()
    #plt.title('title')
    #plt.xlabel('#of mail registered')      
    #for i, v in enumerate(nhosts):
    #    ax.text(v + 3, i + .25, str(v), color='blue', fontweight='bold')
    #plt.subplots_adjust(left=0.2, right=0.9, top=0.9, bottom=0.1)
    #plt.savefig("host_counter.svg")
    fp = open('data/host_mail.csv', 'w', 0)
    csv.writer(fp, delimiter=',', quoting=csv.QUOTE_NONE)
    csv.writerows(domain_dict.items())
    fp.close()

    deleted_mail_dict = defaultdict(lambda: 0)
    for host in domain_dict.iterkeys():
        try:
            records = dns.resolver.query(host, "MX")
            for name in domain_dict[host]:
                if verify_mail(records, name+"@"+host):
                    ok += 1
                else:
                    deleted_mail_dict[host] += 1
        except NXDOMAIN:
            down.add(host)

    print "Domains unreachable: ", len(down)

    down_i = (len(down)*100.0/len(domains), "Domains unreachable", 0.0)
    total_i = (100 - down_i[0], "total domains", 0.0)
    bake((total_i, down_i), "Domain reachability")

    ok_i = (ok*100.0/total_userid, "reachable addresses", 0.1)
    no_mail_i = (no_mail*100.0/total_userid, "no mail provided", 0.0)
    grand_i = (100 - ok_i[0] - no_mail_i[0], "total uids", 0.0)
    bake((ok_i, no_mail_i, grand_i), "User_id_cake.svg")

    domains, nhosts = zip(*domain_counter[:15])
    ndowns = [deleted_mail_dict[d] for d in domains]
    fig, ax = plt.subplots() 
    width = 0.75 # the width of the bars 
    ind = range(len(domains))  # the x locations for the groups
    ax.barh(ind, nhosts, width, color="gold")
    ax.barh(ind, ndowns, width, color="silver")
    ax.set_yticks(ind)
    ax.set_yticklabels(domains, minor=False)
    ax.invert_yaxis()
    plt.title('title')
    plt.xlabel('#of mail registered')      
    for i, v in enumerate(nhosts):
        ax.text(v + 3, i + .25, str(v), color='blue', fontweight='bold')
    for i, v in enumerate(ndowns):
        ax.text(v + 3, i + .25, str(v), color='blue', fontweight='bold')
    plt.subplots_adjust(left=0.2, right=0.9, top=0.9, bottom=0.1)
    plt.savefig("mail_up_down_counter.svg")
    print "Saved", "mail_up_down_counter.svg"



def bake(lst, title, overlap=False):
    if len(lst) < 2:
        raise AttributeError("cannot make a cake with less than 2 ingredients")
    plt.clf()
    fig1, ax1 = plt.subplots()
    data, labels, explode = zip(*lst)
    datas, texts, autotexts = ax1.pie(data, explode=explode, labels=labels, autopct='%1.1f%%',
            shadow=True, startangle=90)
    ax1.axis('equal')
    if overlap:
        i=0
        for d, txt in zip(datas, autotexts):
            # the angle at which the text is located
            ang = (d.theta2 + d.theta1) / 2.
            # new coordinates of the text, 0.7 is the distance from the center 
            x = d.r * (0.6 + i) * np.cos(ang*np.pi/180)
            y = d.r * (0.6 + i) * np.sin(ang*np.pi/180)
            i += 0.15
            # if patch is narrow enough, move text to new coordinates
            if (d.theta2 - d.theta1) < 10.:
                txt.set_position((x, y))
    plt.savefig(title)
    print "Saved", title
    plt.clf()

def security(args):
    algorithms_map={
            1: "RSA",
            2: "RSA (Encrypt Only)",
            3: "RSA (Sign Only)",
            16: "Elgamal",
            17: "DSA",
            18: "ECDH",
            19: "ECDSA",
            20: "Reserved Elgamal",
            21: "Reserved DH",
            22: "EdDSA"
            }

    rsa_year_size_dict={}
    dsa_year_size_dict={}
    elgamal_year_size_dict={}
    key_dimensions={}

    for pubkey in Pubkey.select():
        pubkey_year_alg_dict[pubkey.creationtime.year].append(algorithms_map[pubkey.algorithm])
        if pubkey.algorithm in [1,2,3]:
            rsa_year_size_dict[pubkey.creationtime.year].append(pubkey.nn)
        elif pubkey.algorithm == 16:
            elgamal_year_size_dict[pubkey.creationtime.year].append(pubkey.p)
        elif pubkey.algorithm == 17:
            elgamal_year_size_dict[pubkey.creationtime.yaer].append((pubkey.p, pubkey.q))
    for signature in Signature.select():
        signature_year_alg_dict[signature.creationtime.year].append(algorithms_map[signature.algorithm])
    
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
        'plot_ptree': plot_ptree,
        'certificates': certificates,
        'userid': userid,
        'security': security
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
  ok Algoritmi usati per encryption e per signature (per anno)
  -- Dimensione delle chiavi (per anno)
  --- RSA modulo (n)
  --- DSA p(1000-3000) e q(100) corrispondenza con tabella
  --- ElGamal p 
  -- Signatures valide / self signatures valide sul totale
  -- Attacchi da formato : curve inesistenti
  -- Attacchi da analyzer: moduli RSA con fattori piccoli/primi

 * Liveness/usage state
  ok # user ID che contengono un indirizzo mail (da regex, istogramma
sovrapposto con i numeri assoluti)
  ok mail domains: statistiche di frequenza, gli MX esistono ancora?

 * (Extra) Chinese keys
 ok il numero di chiavi residenti nel DB in quell' anno, create in anni
 precedenti
 ok il numero di chiavi create in quell' anno, non appartenenti a questo
 formato
 ok il numero di chiavi create in quell' anno appartenenti a questo formato
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
