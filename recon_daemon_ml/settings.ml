(***********************************************************************)
(* settings.ml - Various and sundry settings with their defaults, plus *)
(*               functions for assigning new values.  This is used by  *)
(*               the getopt routines to set preferences                *)
(*                                                                     *)
(* Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, *)
(*               2011, 2012, 2013  Yaron Minsky and Contributors       *)
(*                                                                     *)
(* This file is part of SKS.  SKS is free software; you can            *)
(* redistribute it and/or modify it under the terms of the GNU General *)
(* Public License as published by the Free Software Foundation; either *)
(* version 2 of the License, or (at your option) any later version.    *)
(*                                                                     *)
(* This program is distributed in the hope that it will be useful, but *)
(* WITHOUT ANY WARRANTY; without even the implied warranty of          *)
(* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU   *)
(* General Public License for more details.                            *)
(*                                                                     *)
(* You should have received a copy of the GNU General Public License   *)
(* along with this program; if not, write to the Free Software         *)
(* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 *)
(* USA or see <http://www.gnu.org/licenses/>.                          *)
(***********************************************************************)

open StdLabels
open MoreLabels
module Unix=UnixLabels
open Printf

let n = ref 0
let set_n value = n := value

let debug = ref true
let set_debug value = debug := value

let debuglevel = ref 3
let set_debuglevel value = debuglevel := value

let mbar = ref 5
let set_mbar value = mbar := value

let bitquantum = ref 2
let set_bitquantum value = bitquantum := value

let drop = ref 10
let set_drop value = drop := value

let bytes = ref 16
let set_bytes value = bytes := value

(** maximum number of differences to recover in one go *)
let max_recover = ref 2000
let set_max_recover value = max_recover := value

let seed = ref 0
let self_seed = ref true
let set_seed value =
  self_seed := false;
  seed := value

let recon_port = ref 11370
let recon_address = ref "0.0.0.0 ::"
let set_recon_address value = recon_address := value

let hkp_port = ref 11371
let hkp_address = ref "0.0.0.0 ::"
let set_hkp_address value = hkp_address := value

let use_port_80 = ref false

let set_base_port value =
  recon_port := value;
  hkp_port := value + 1

let set_recon_port value = recon_port := value
let set_hkp_port value = hkp_port := value

let setup_RNG () =
  if !self_seed
  then Random.self_init ()
  else Random.init !seed

let max_internal_matches = ref 20000
let set_max_internal_matches value = max_internal_matches := value

let max_matches = ref 500
let set_max_matches value = max_matches := value

let max_outstanding_recon_requests = ref 100
let set_max_outstanding_recon_requests value =
  max_outstanding_recon_requests := value

let max_uid_fetches = ref 1000
let set_max_uid_fetches value = max_uid_fetches := value

(* whether or not to use a disk-based prefix-tree implementation *)
let disk_ptree = ref true

let max_ptree_nodes = ref 1000
let set_max_ptree_nodes value = max_ptree_nodes := value

let http_fetch_size = ref 100
let set_http_fetch_size value = http_fetch_size := value

let prob = ref 0.1
let set_prob value = prob := value

let recon_sync_interval = ref (5. *. 60.)
let set_recon_sync_interval value = recon_sync_interval := value

let gossip_interval = ref 60. (* time between gossips in seconds*)
let set_gossip_interval value = gossip_interval := value *. 60.

let gossip = ref true (* whether or not to initiate gossips *)

let anonlist = ref ([] : string list)

let cache_bytes = ref (Some (20 * 1024 * 1024))
let set_cache_bytes value = cache_bytes := Some (value * 1024 * 1024)

let pagesize = ref (Some 65536)
let set_pagesize value = pagesize := Some (value * 512)

let ptree_cache_bytes = ref (Some (5 * 1024 * 1024))
let set_ptree_cache_bytes value =
  ptree_cache_bytes := Some (value * 1024 * 1024)

let ptree_pagesize = ref (Some 4096)
let set_ptree_pagesize value = ptree_pagesize := Some (value * 512)

let hostname = ref (Unix.gethostname ())
let set_hostname value = hostname := value

let nodename = ref (Unix.gethostname ())
let set_nodename value = nodename := value

let server_contact = ref ""
let set_server_contact value = server_contact := value

let filelog = ref true

let transactions = ref true

let checkpoint_interval = ref (60. *. 60.)
let set_checkpoint_interval value = checkpoint_interval := value

let recon_checkpoint_interval = ref (60. *. 60.)
let set_recon_checkpoint_interval value = recon_checkpoint_interval := value

let ptree_thresh_mult = ref 10
let set_ptree_thresh_mult value = ptree_thresh_mult := value

let recon_thresh_mult = ref 30
let set_recon_thresh_mult value = recon_thresh_mult := value

let wserver_timeout = ref 180
let set_wserver_timeout value = wserver_timeout := value

let reconciliation_config_timeout = ref 45
let set_reconciliation_config_timeout value =
  reconciliation_config_timeout := value

let reconciliation_timeout = ref (60 * 60)
let set_reconciliation_timeout value = reconciliation_timeout := (value * 60)

let initial_stat = ref false (* whether to calculate stats page on boot *)

let stat_calc_hour = ref 3 (* hour of the day to do stats calculation *)
let set_stat_calc_hour value = stat_calc_hour := value


let missing_keys_timeout = ref 180
let set_missing_keys_timeout value = missing_keys_timeout := value

let command_timeout = ref 60
let set_command_timeout value = command_timeout := value

let sendmail_cmd = ref "sendmail -t -oi"
let set_sendmail_cmd value = sendmail_cmd := value

let membership_reload_time = ref (60. *. 60. *. 6.)
let set_membership_reload_time value =
  membership_reload_time := value *. 60. *. 60.

(** WHether to log hashes of most-recently-found diff *)
let log_diffs = ref true

let from_addr = ref None
let set_from_addr value = from_addr := Some value
let get_from_addr () =
  match !from_addr with
    | Some addr -> addr
    | None ->
        let addr = ((Unix.getpwuid (Unix.getuid ())).Unix.pw_name
                           ^ "@" ^ !hostname)
        in
        from_addr := Some addr;
        addr

let use_stdin = ref false

let basedir = ref "."

let base_ptree_dbdir = "PTree"
let base_membership_file = "membership"
let base_msgdir = "messages"
let base_failed_msgdir = "failed_messages"

let filters = ["yminsky.dedup";"yminsky.merge"]

let ptree_dbdir = lazy (Filename.concat !basedir base_ptree_dbdir)
let membership_file = lazy (Filename.concat !basedir base_membership_file)
let msgdir = lazy (Filename.concat !basedir base_msgdir)
let failed_msgdir = lazy (Filename.concat !basedir base_failed_msgdir)

(*****************************************************************)

(** Specifies the options along with the corresponding actions.
  These are used both for command-line options and the config file *)
let parse_spec =
  [ ("-debug", Arg.Set debug, " debugging mode");
    ("-debuglevel", Arg.Int set_debuglevel,
     " Debugging level -- sets verbosity of logging");
    ("-q", Arg.Int set_bitquantum, " number of bits defining a bin");
    ("-mbar", Arg.Int set_mbar, " number of errors that can be corrected " ^
       "in one shot");
    ("-seed", Arg.Int set_seed, " Seed used by RNG");
    ("-hostname", Arg.String set_hostname, " current hostname");
    ("-nodename", Arg.String set_nodename, " current nodename");
    ("-d", Arg.Int set_drop, " Number of keys to drop at random " ^
       "when synchronizing");
    (*("-max_internal_matches", Arg.Int set_max_internal_matches,
     " Maximum number of matches for most specific word in a " ^
     "multi-word search");*)
    ("-max_matches", Arg.Int set_max_matches,
     " Maximum number of matches that will be returned from a query");
    ("-ptree_pagesize", Arg.Int set_ptree_pagesize,
     " Pagesize in 512 byte blocks for prefix tree db");
    ("-ptree_cache", Arg.Int set_ptree_cache_bytes,
     " Cache size in megs for prefix tree db");
    ("-baseport",Arg.Int set_base_port, " Set base port number");
    ("-logfile",Arg.String (fun _ -> ()), " DEPRECATED.  Now ignored.");
    ("-recon_port",Arg.Int set_recon_port, " Set recon port number");
    ("-recon_address",Arg.String set_recon_address, " Set recon binding address by hostname or IP");
    ("-basedir", Arg.Set_string basedir, " Base directory");
    ("-stdoutlog", Arg.Clear filelog,
     " Send log messages to stdout instead of log file");
    ("-diskptree", Arg.Set disk_ptree,
     " Use a disk-based ptree implementation. Slower, but requires far less memory");
    ("-nodiskptree", Arg.Clear disk_ptree, " Use in-mem ptree");
    ("-max_ptree_nodes", Arg.Int set_max_ptree_nodes,
     " Maximum number of allowed ptree nodes. Only meaningful if -diskptree is set");
    ("-prob", Arg.Float set_prob, " Set probability. Used for testing code only");
    ("-recon_sync_interval", Arg.Float set_recon_sync_interval,
     " Set sync interval for reconserver.");
    ("-gossip_interval", Arg.Float set_gossip_interval, " Set time between " ^
       "gossips in minutes.");
    ("-dontgossip", Arg.Clear gossip, " Don't gossip automatically.  " ^
       "Host will still respond to requests from other hosts");
    (*("-checkpoint_interval", Arg.Float set_checkpoint_interval,
     " Time period between checkpoints");*)
    ("-recon_checkpoint_interval", Arg.Float set_recon_checkpoint_interval,
     " Time period between checkpoints for reconserver");
    ("-ptree_thresh_mult", Arg.Int set_ptree_thresh_mult,
     " Multiple of thresh which specifies minimum node size in prefix tree");
    ("-recon_thresh_mult", Arg.Int set_recon_thresh_mult,
     " Multiple of thresh which specifies minimum node size that is " ^
     "included in reconciliation");
    ("-max_recover", Arg.Int set_max_recover,
     " Maximum number of differences to recover in one round");
    ("-http_fetch_size", Arg.Int set_http_fetch_size,
     " Number of keys for reconserver to fetch from dbserver in one go.");
    ("-wserver_timeout", Arg.Int set_wserver_timeout,
     " Timeout in seconds for webserver requests");
    ("-reconciliation_timeout", Arg.Int set_reconciliation_timeout,
     " Timeout for reconciliation runs in minutes");
    (*("-stat_hour", Arg.Int set_stat_calc_hour,
     " Hour at which to run database statistics");
    ("-initial_stat", Arg.Set initial_stat,
     " Runs database statistics calculation on boot");*)
    ("-reconciliation_config_timeout", Arg.Int set_reconciliation_config_timeout,
     " Set timeout in seconds for initial exchange of config info " ^
     "in reconciliation");
    ("-missing_keys_timeout", Arg.Int set_missing_keys_timeout,
     " Timeout in seconds for get_missing_keys");
    ("-command_timeout", Arg.Int set_command_timeout,
     " Timeout in seconds for commands set over command socket");
    (*("-sendmail_cmd", Arg.String set_sendmail_cmd,
     " Command used for sending mail");
    ("-from_addr", Arg.String set_from_addr,
     " From address used in synchronization emails used to communicate " ^
     "with PKS");*)
    ("-max_outstanding_recon_requests", Arg.Int set_max_outstanding_recon_requests,
     " maximum number of outstanding requests in reconciliation");
    ("-membership_reload_interval", Arg.Float set_membership_reload_time,
     " maximum interval (in hours) at which membership file is reloaded");
    ("-disable_log_diffs", Arg.Clear log_diffs,
     " Disable logging of recent hashset diffs.");
    (*("-stdin", Arg.Set use_stdin,
     " Read keyids from stdin (sksclient only)");*)
    ("-server_contact", Arg.String set_server_contact,
     " Set OpenPGP KeyID of the server contact");
  ]

let parse_spec = Arg.align parse_spec

let anon_options option_string =
  anonlist := option_string::!anonlist

let usage_string =
  "sks command [-mbar mbar] [-q bitquantum] -debug  (type \"sks help\" for a list of commands)"



