(***********************************************************************)
(* fingerprint.ml - Computes PGP fingerprints and keyids               *)
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

open Printf
open StdLabels
open MoreLabels
open Common

open Packet
module Set = PSet.Set

(* Compute PGP Key Fingerprint and PGP KeyIDs *)

(* v3 and v4 fingerprints and keyids are quite different.

   v3 fingerprint: MD5 sum of concatenation of bodies of MPI's
                   for modulus and exponent of RSA key

   v3 keyid: low 64 bits of public modulus of RSA key

   v4 fingerprint: 160-bit SHA-1 hash of:
        Packet Tag (1 octet)
        packet length (2 octets)
        entire public key packet (starting with version field)

   v4 KeyID: last 64 bits of fingerprint
*)


type result = { fp : string;
                keyid : string;
              }

let from_packet packet =
  let cin = new Channel.string_in_channel packet.packet_body 0 in
  let version = cin#read_byte in
  match version with
      2 | 3 ->
        let hash = Cryptokit.Hash.md5 () in
        (* print_string "v3 pubkey\n"; *)
        cin#skip 7;
        (* skip creation time (4 octets), days of validity (2 octets)
           and algorithm type (1 octet) *)
        let n = ParsePGP.read_mpi cin in (* modulus *)
        let e = ParsePGP.read_mpi cin in (* exponent *)
        hash#add_substring n.mpi_data 0 ((n.mpi_bits + 7)/8);
        hash#add_substring e.mpi_data 0 ((e.mpi_bits + 7)/8);
        let fingerprint = hash#result
        and keyid =
          let len = String.length n.mpi_data in
          String.sub n.mpi_data ~pos:(len - 8) ~len:8
        in
        hash#wipe;
        { fp = fingerprint;
          keyid = keyid;
        }

    | 4 ->
        let hash = Cryptokit.Hash.sha1 () in
        hash#add_byte 0x99;
        (* This seems wrong.  The spec suggests that packet.packet_tag
           is what should be used here.  But this is what's done in the GPG
           codebase, so I'm copying it. *)
        hash#add_byte ((packet.packet_length lsr 8) land 0xFF);
        hash#add_byte (packet.packet_length land 0xFF);
        hash#add_string packet.packet_body;
        let fingerprint = hash#result in
        let keyid =
          let len = String.length fingerprint in
          String.sub fingerprint ~pos:(len - 8) ~len:8
        in
        hash#wipe;
        { fp = fingerprint;
          keyid = keyid;
        }

    | _ ->
        failwith "Fingerprint.from_packet: Unexpected version number"

let rec from_key key = match key with
    packet::key_tail ->
      if  packet.packet_type = Public_Key_Packet
      then from_packet packet
      else from_key key_tail
  | [] ->
      raise Not_found

let shorten ~short keyid =
  if short then String.sub ~pos:4 ~len:4 keyid else keyid

let fp_from_key key = (from_key key).fp
let keyid_from_key ?(short=true) key =
  let keyid = (from_key key).keyid in
  shorten ~short keyid
;;