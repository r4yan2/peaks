(***********************************************************************)
(* keydb.ml - Interface for dealing with underlying key database       *)
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
open Printf
open Common
module P = Mysql.Prepared
module Set = PSet.Set
let s = String.copy
let db_mysql = Mysql.quick_connect ~database:(s Db_settings.database) ~host:(s Db_settings.host)
                              ~user:(s Db_settings.user) ~password:(s Db_settings.password)()

open Packet


module type RestrictedKeydb =
sig

  val close_dbs : unit -> unit

  (** access methods *)
  val get_new_key : int -> string list
  val set_as_sync : string -> unit
  val get_removed_hash : unit -> string list
  val delete_removed_hash : string -> unit
  val create_hashstream : unit -> string SStream.sstream * (unit -> unit)

  type 'a offset = { fnum : int; pos : 'a; }
  and skey =
      KeyString of string
    | Key of Packet.packet list
    | Offset of int offset
    | LargeOffset of int64 offset
  type key_metadata = {
    md_hash : string;
    md_skey : skey;
  }
  val key_to_metadata : ?hash:Digest.t -> key -> key_metadata
  val insert_key : string -> unit
end


module Unsafe =
struct
  (**********************************************************)
  (*  Types  ************************************************)
  (**********************************************************)


  type 'a offset = { fnum: int; pos: 'a; }

  (** Stored key.  Can have a number of formats.
    Eventually this may include death certificates
  *)
  type skey =
    | KeyString of string
    | Key of packet list
    | Offset of int offset
    | LargeOffset of int64 offset

  (***********************************************************************)
  (*  Key conversions ****************************************************)
  (***********************************************************************)

  let marshal_offset cout offset =
    cout#write_int offset.fnum;
    cout#write_int offset.pos

  let unmarshal_offset cin =
    let fnum = cin#read_int in
    let offset = cin#read_int in
    { fnum = fnum; pos = offset; }

  (***********************************************************************)

  let marshal_large_offset cout offset =
    cout#write_int offset.fnum;
    cout#write_int64 offset.pos

  let unmarshal_large_offset cin =
    let fnum = cin#read_int in
    let offset = cin#read_int64 in
    { fnum = fnum; pos = offset; }


  (***********************************************************************)

  let skey_of_string s =
    let cin = new Channel.string_in_channel s 0 in
    match cin#read_byte with
        0 -> KeyString cin#read_rest
      | 1 -> Offset (unmarshal_offset cin)
      | 2 -> LargeOffset (unmarshal_large_offset cin)
      | _ -> failwith "Unexpected skey type"

  let skey_to_string skey =
    let cout = Channel.new_buffer_outc 0 in
    (match skey with
         KeyString s -> cout#write_byte 0; cout#write_string s
       | Key key -> cout#write_byte 0; Key.write key cout
       | Offset offset -> cout#write_byte 1; marshal_offset cout offset
       | LargeOffset offset -> cout#write_byte 2;
           marshal_large_offset cout offset
    );
    cout#contents

  let key_of_skey skey =
    match skey with
        KeyString s -> Key.of_string s
      | Key key -> key
      | _ -> failwith ("Cannot convert skey")

  (*let key_to_string key = skey_to_string (Key key)*)
  let key_of_string s = key_of_skey (skey_of_string s)

  (***********************************************************************)

  (***********************************************************************)

  let close_dbs () =
    Mysql.disconnect db_mysql

  (***********************************************************************)
  (*  Access methods  ***************************************************)
  (***********************************************************************)

  let get_skeystring_by_hash hash =
    let get_res t =
      match P.fetch t with
      | Some arr -> Array.get arr 0
      | None -> raise Not_found
    in
    let get = P.create db_mysql (s "SELECT CONCAT(0x00, certificate) FROM 
                gpg_keyserver WHERE hash = (?)") in 
    let res = get_res (P.execute get [|s (KeyHash.hexify hash)|]) in
    P.close get;
    BatOption.default "" res

  (***********************************************************************)

  (** returns true iff db contains specified hash *)
  let has_hash hash =
    try ignore (get_skeystring_by_hash hash); true
    with Not_found -> false

  (***********************************************************************)

  let get_skeystrings_by_fingerprint ~fp ~version =
    let fp = if version == 4 then fp else (KeyHash.hexify fp) ^ "00000000" in
    let rec loop t =
      match P.fetch t with
      | Some arr -> [BatOption.default "" (Array.get arr 0)] @ loop t
      | None -> []
    in
    let get_cert_by_fp = P.create db_mysql (s "SELECT CONCAT(0x00, certificate) FROM gpg_keyserver 
                                              WHERE version = (?) and fingerprint = UNHEX(?);") in 
    let arr = loop (P.execute get_cert_by_fp [|string_of_int version; s fp|]) in
    P.close get_cert_by_fp;
    List.map ~f:key_of_string arr

  (***********************************************************************)

  let create_hashstream () =
    plerror 3 "create_hashstream";
    let rec loop t = 
      match P.fetch t with
      | Some arr -> (BatOption.default "" (Array.get arr 0)) :: loop t
      | None -> []
    in
    let get_all_hash = P.create db_mysql (s "SELECT UNHEX(hash) FROM gpg_keyserver;") in 
    let res = ref (loop (P.execute get_all_hash [||])) in
    let first = (try 
                  let elm = List.hd !res in
                  res := List.tl !res;
                  elm;
                with
                  Failure "hd" -> ""
    ) in
    let next () = (try Some (
                    let elm = List.hd !res in
                    ignore (res := List.tl !res);
                    elm;)
                  with
                    Failure "hd" -> None) in
    let close () = (P.close get_all_hash) in
    let stream = SStream.make ~first next in
    (stream,close)

  (**************************************************************)
  (**  Functions for updating key database *)
  (**************************************************************)

  type key_metadata = { md_hash: string;
                        md_skey: skey;
                      }

  let key_to_metadata ?hash key =
    { md_hash = (match hash with
                   | None -> KeyHash.hash key
                   | Some hash -> hash);
      md_skey = Key key;
    }

  (****************************************************************)

  let apply_md_updates updates =
    for i = 0 to Array.length updates - 2 do
      if (updates.(i)).md_hash = (updates.(i+1)).md_hash
      then failwith ("Keydb.apply_md_updates_txn: duplicate hashes " ^
                     "found in update list")
    done;

    
    plerror 3 "Begin Insert";
    let insert = P.create db_mysql (s "INSERT INTO gpg_keyserver 
                      (version, ID, fingerprint, certificate, hash, is_synchronized) 
                      VALUES (?,CONV(?,16,10),?,substring(?, 2),?,0) 
                      ON DUPLICATE KEY UPDATE certificate = substring(?, 2), hash = ?, 
                      is_synchronized = 0;") in
    let insert_uid = P.create db_mysql (s "INSERT IGNORE INTO UserID 
                              (ownerkeyID, fingerprint, name, email, is_analyze, bindingAuthentic) 
                              VALUES (CONV(?,16,10),?,?,?,0,0);") in
    
    Array.iter updates
      ~f:(function md ->
              let packet_list = key_of_skey md.md_skey in
              let cin = new Channel.string_in_channel (List.hd packet_list).packet_body 0 in
              let version = cin#read_byte in
              ignore (P.execute insert [|
                    string_of_int version; 
                    s (KeyHash.hexify (Fingerprint.keyid_from_key ~short:false packet_list)); 
                    s ((Fingerprint.fp_from_key packet_list)); 
                    s (skey_to_string md.md_skey); 
                    s (KeyHash.hexify md.md_hash);
                    s (skey_to_string md.md_skey); 
                    s (KeyHash.hexify md.md_hash)|]);
              List.iter ~f:(fun p -> 
                if p.packet_type == Packet.User_ID_Packet then 
                  let name = p.packet_body in
                  plerror 3 "%s" name;
                  let email = try 
                    let rxp_email = Pcre.regexp "(?:(?:[^<>()\\[\\].,;:\\s@\"]+(?:\\.[^<>()\\[\\].,;:\\s@\"]+)*)|\".+\")@(?:(?:[^<>()‌​\\[\\].,;:\\s@\"]+\\.)+[^<>()\\[\\].,;:\\s@\"]{2,})" in
                    Pcre.get_subject (Pcre.exec ~rex:rxp_email name);
                  with
                    Not_found -> plerror 10 "Email not found"; ""
                    in
                  ignore (P.execute insert_uid [|
                    s (KeyHash.hexify (Fingerprint.keyid_from_key ~short:false packet_list)); 
                    s ((Fingerprint.fp_from_key packet_list));
                    s (B64.encode name);
                    s (B64.encode email)
                  |]);
                  ();
              ) packet_list;
          );

    ignore (P.close insert);
    ignore (P.close insert_uid);
    ()


 (***********************************************************************)

  let key_to_merge_updates key =
    let hash = KeyHash.hash key in
    try
      if has_hash hash then [] else
        let fp = Fingerprint.fp_from_key key in
        let cin = new Channel.string_in_channel (List.hd key).packet_body 0 in
        let version = cin#read_byte in
        let potential_merges = List.filter ~f:(fun x -> x <> key)
                                 (get_skeystrings_by_fingerprint ~fp ~version)
        in
        plerror 4 "%d potential merges found for fingerprint %s"
          (List.length potential_merges) (KeyHash.hexify fp);
        if List.length potential_merges > 1 then failwith "Too many keys found for a single fingerprint";
        
        let updates = if (List.length potential_merges) == 0 then [key] else
                match KeyMerge.merge key (List.hd potential_merges) with
                  | None -> [key]
                  | Some mergedKey -> [mergedKey] in
        let updates = List.map updates
                        ~f:(fun (key) -> (key_to_metadata key))
        in
        plerror 4 "%d key(s) ready for insertion" (List.length updates);
        updates
    with
      | Sys.Break | Eventloop.SigAlarm as e -> raise e
      | e ->
          eplerror 2 e "Keydb.key_to_merge_updates: error in key %s"
            (KeyHash.hexify hash);
          []

  let insert_key cert = 
    let updates = key_to_merge_updates (key_of_string ("\x00" ^ cert)) in
    apply_md_updates (Array.of_list updates)

  (**********************************************************)

  let get_new_key count =
    let rec loop t =
    match P.fetch t with
      | Some arr -> (BatOption.default "" (Array.get arr 0)) :: loop t
      | None -> []
    in
    let get_key = P.create db_mysql (s "SELECT UNHEX(hash) FROM gpg_keyserver WHERE is_synchronized = 0 LIMIT ?") in
    let res = loop (P.execute get_key [|string_of_int count|]) in
    P.close get_key;
    res

  let set_as_sync hash =
    let update_key = P.create db_mysql (s "UPDATE gpg_keyserver SET is_synchronized = 1 WHERE hash = ?;") in
    ignore (P.execute update_key [|s (KeyHash.hexify hash)|]);
    P.close update_key;
    ()

  let get_removed_hash () =
    let rec loop t =
    match P.fetch t with
      | Some arr -> (BatOption.default "" (Array.get arr 0)) :: loop t
      | None -> []
    in
    let get_hashes = P.create db_mysql (s "SELECT UNHEX(hash) FROM removed_hash") in
    let res = loop (P.execute get_hashes [||]) in
    P.close get_hashes;
    res
  
  let delete_removed_hash h =
    let remove_hash = P.create db_mysql (s "DELETE FROM removed_hash WHERE hash = ?;") in
    ignore (P.execute remove_hash [|s (KeyHash.hexify h)|]);
    P.close remove_hash;
    ()

end


module Safe = (Unsafe : RestrictedKeydb)
